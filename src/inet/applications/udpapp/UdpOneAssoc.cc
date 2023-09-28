//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2004,2011 Andras Varga
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is based on "src/inet/applications/udpapp/UdpSink.cc".
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/applications/udpapp/UdpOneAssoc.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

//FILS
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/common/Simsignals.h"
#include "inet/common/lifecycle/NodeStatus.h"

namespace inet {

Define_Module(UdpOneAssoc);

UdpOneAssoc::~UdpOneAssoc()
{
    cancelAndDelete(selfMsg);
}

void UdpOneAssoc::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);

        localPort = par("localPort");
        destPort = par("destPort");
        destPortFils = par("destPortFils");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        // get the hostname
        host = getContainingNode(this);
        // for a wireless interface subscribe the association event to start the DHCP protocol
        host->subscribe(l2AssociatedSignal, this);
        host->subscribe(enableFilsSignal, this);
        host->subscribe(l2DisassociatedSignal, this);
        socket.setCallback(this);
        socket.setOutputGate(gate("socketOut"));
        //get interface entry
        auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        auto interfaceName = "wlan0"; // fixed interface for response
        //getInterfaceId
        cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
             ie = interfaceTable->getInterface(i);
             if (interfaceMatcher.matches(ie->getInterfaceName())){
                 break;
             }
        }
    }
}

void UdpOneAssoc::receiveSignal(cComponent *source, int signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();
    printSignalBanner(signalID, obj, details);

    // host associated. link is up. change the state to init.
    if (signalID == l2AssociatedSignal) {
        InterfaceEntry *associatedIE = check_and_cast_nullable<InterfaceEntry *>(obj);
        if (associatedIE && ie == associatedIE) {
            EV_INFO << "Interface associated, starting app." << endl;
            isAssociated = true;            
        }
    }
    else if (signalID == enableFilsSignal) {
        InterfaceEntry *associatedIE = check_and_cast_nullable<InterfaceEntry *>(obj);
        if (associatedIE && ie == associatedIE) {
            EV_INFO << "FILS is enabled. ovewrite destPort <= destPortFils" << endl;
            destPort = destPortFils;
        }
    }
    else if (signalID == l2DisassociatedSignal) {
        InterfaceEntry *associatedIE = check_and_cast_nullable<InterfaceEntry *>(obj);
        if (associatedIE && ie == associatedIE) {
            EV_INFO << "[UdpOneAssoc::receiveSignal] Disassociated from AP. Resetting authentication status." << endl;
            cancelEvent(selfMsg);
            isAssociated = false;
            selfMsg->setKind(START);
            scheduleAt(simTime()+ .1, selfMsg); // next polling
        }
    }
}

void UdpOneAssoc::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void UdpOneAssoc::setSocketOptions()
{
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *multicastInterface = par("multicastInterface");
    if (multicastInterface[0]) {
        IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        InterfaceEntry *ie = ift->findInterfaceByName(multicastInterface);
        if (!ie)
            throw cRuntimeError("Wrong multicastInterface setting: no interface named \"%s\"", multicastInterface);
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    bool receiveBroadcast = par("receiveBroadcast");
    if (receiveBroadcast)
        socket.setBroadcast(true);

    bool joinLocalMulticastGroups = par("joinLocalMulticastGroups");
    if (joinLocalMulticastGroups) {
        MulticastGroupList mgl = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        socket.joinLocalMulticastGroups(mgl);
    }
    socket.setCallback(this);
}

L3Address UdpOneAssoc::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

void UdpOneAssoc::sendPacket()
{
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    if(dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = chooseDestAddr();
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void UdpOneAssoc::processStart()
{
    if (isAssociated) {
        EV << "[UdpOneAssoc::processStart] Interface is associated." << endl;
    
        if (!isInitialized) {
            socket.setOutputGate(gate("socketOut"));
            const char *localAddress = par("localAddress");
            socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
            setSocketOptions();

            const char *destAddrs = par("destAddresses");
            cStringTokenizer tokenizer(destAddrs);
            const char *token;
            while ((token = tokenizer.nextToken()) != nullptr) {
                destAddressStr.push_back(token);
                L3Address result;
                L3AddressResolver().tryResolve(token, result);
                if (result.isUnspecified())
                    EV_ERROR << "[UdpOneAssoc::processStart] Cannot resolve destination address: " << token << endl;
                destAddresses.push_back(result);
            }
            isInitialized = true;
        }

        processSend();
    } 
    else {
        EV << "[UdpOneAssoc::processStart] Interface is not associated yet - will check again in 100ms." << endl;
        cancelEvent(selfMsg);
        selfMsg->setKind(START);
        scheduleAt(simTime()+ .1, selfMsg); // next polling
    }
}

void UdpOneAssoc::processSend()
{
    if (isAssociated) {
        EV << "[UdpOneAssoc::processSend] DHCP message sent" << endl;
        sendPacket();
    }

    // Unless disabled, another DHCP message will be sent 
    // in a designated interval.
    cancelEvent(selfMsg);
    simtime_t d = simTime() + par("sendInterval");
    if (stopTime < SIMTIME_ZERO || d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleAt(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleAt(stopTime, selfMsg);
    }
}

void UdpOneAssoc::processStop()
{
    socket.close();
}

void UdpOneAssoc::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void UdpOneAssoc::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void UdpOneAssoc::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void UdpOneAssoc::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void UdpOneAssoc::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void UdpOneAssoc::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
    delete pk;
    numReceived++;
}

void UdpOneAssoc::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t timeToStart = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (timeToStart < stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(timeToStart, selfMsg);
    }
}

void UdpOneAssoc::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void UdpOneAssoc::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.destroy();         //TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

} // namespace inet

