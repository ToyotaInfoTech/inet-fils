//
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 3
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

#include "inet/applications/udpapp/UdpEchoApp.h"
#include "inet/applications/udpapp/UdpEchoAppDelay.h"
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"


namespace inet {

Define_Module(UdpEchoAppDelay);

UdpEchoAppDelay::~UdpEchoAppDelay()
{
    cancelAndDelete(reSendTo);
    //delete pkt_to;
}

void UdpEchoAppDelay::initialize(int stage)
{
    UdpEchoApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        reSendTo = new cMessage("Re-Send timeout");
    }
}

void UdpEchoAppDelay::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()){
        if (msg->getKind() == RE_SEND_TIMEOUT) {
            EV << "UdpEchoAppDelay:RE_SEND_TIMEOUT, reSendFlag:" << reSendFlag << ", time:" << simTime() << endl;
            if (reSendFlag == 0){
                EV << "[reSendFlag==0]Under next send pkt processing ignored" << endl;
                return;
            }
            // re-send packet
            //socket.sendTo(pkt_to, remoteAddressTo, srcPortTo);
            makeSendPacket(remoteAddressTo, srcPortTo, msgLength, counter);
            reSendTimeout();
            return;
        }
    }
    socket.processMessage(msg);
}

void UdpEchoAppDelay::socketDataArrived(UdpSocket *socket, Packet *pk)
{
    EV << "UdpEchoAppDelay::socketDataArrived\n";

    if (pk->isSelfMessage()){
        EV << "after delay time, stop reSend" << endl;
        // stop re-send
        reSendFlag = 0;
        cancelEvent(reSendTo);
        sendEcho(pk);
        return;
    }
    //pk->trim();

    double delay = par("delayTime");
    if (delay >= 0) {
        EV << "UdpEchoAppDelay::socketDataArrived:scheduleAt\n";
        scheduleAt(simTime() + delay, pk); // send after a delay
        // statistics
        numEchoed++;
        emit(packetSentSignal, pk);
    } else {
        // no send back
        EV << "UdpEchoAppDelay::socketDataArrived:No sendTo:delay=" << delay << "\n";
    }
}

bool UdpEchoAppDelay::reSendTimeout()
{
    // set re-send timeout
    EV << "reSendTimeout" << endl;
    double timeOut = par("reSendTimeout");
    if (timeOut <= 0.0) {
        return false;
    }
    cancelEvent(reSendTo);
    reSendTo->setKind(RE_SEND_TIMEOUT);
    scheduleAt(simTime() + timeOut, reSendTo);
    reSendFlag++;
    return true;
}

void UdpEchoAppDelay::sendEcho(Packet *pkt)
{
    EV << "UdpEchoApp::sendEcho" << endl;

    if (0 == reSendFlag) {
        //set sequence number
        auto bytesChunk = pkt->peekDataAsBytes();
        int seqNo = bytesChunk->getByte(0);
        EV << "sendEcho:reSendFlag:0, counter(prev):" << counter << ", seqNo:" << seqNo
                << ", data:" << bytesChunk << endl;
        if (counter < seqNo) {
            EV << "discard msg: counter < seqNo" << endl;
            return;
        }
        counter++;
    }
    int count = par("count");
    if ( count < counter) {
        //get MAC address(wlan0:only STA)

        InterfaceEntry* interfaceEntry = nullptr;
        auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        auto interfaceName = "wlan0"; // fixed interface for response
        //getInterfaceId
        cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
             interfaceEntry = interfaceTable->getInterface(i);
             if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                 break;
             }
        }
        if (interfaceEntry) {
             //do nothing
        } else {
             throw cRuntimeError("Can not get Interface id (wlan0)");
        }
        auto macAddr = interfaceEntry->getMacAddress();
        auto addr = pkt->getTag<L3AddressInd>()->getDestAddress();
        EV << "STA UdpEchoAppDelay_counter_limit_reached:" << simTime() << " " << addr << ", Mac:"<< macAddr << endl;

        cancelEvent(reSendTo);
        //handleStopOperation(nullptr);
//### log
        std::ostringstream str;
        str << "[01]SendUDPFinish(" << macAddr << ")";
        recordScalar(str.str().c_str(), simTime());
//###
        return;
    }
    L3Address remoteAddress = pkt->getTag<L3AddressInd>()->getSrcAddress();
    int srcPort = pkt->getTag<L4PortInd>()->getSrcPort();
    int remotePortSameAsLocal = par("remotePortSameAsLocal");
    if ( remotePortSameAsLocal ) {
        srcPort = pkt->getTag<L4PortInd>()->getDestPort(); // fixed remote port is local port
    }
    // overwrite remoteAdddress and srcPort
    const char * svr = par("remoteSvrAddr");
    if ( 0 != strlen(svr) ) {
        const char *destAddr = par("remoteSvrAddr");
        L3Address result;
        L3AddressResolver().tryResolve(destAddr, result);
        if (result.isUnspecified()) {
            EV_ERROR << "cannot resolve destination address: " << destAddr << endl;
        } else {
            remoteAddress = result;
            EV << "rewrite destination Address:" << remoteAddress << endl;
        }
        int localPort = par("localPort");
        if (0 != localPort ) {
            srcPort = par("localPort");
        }
    }
    pkt->clearTags();
    pkt->trim();
    // send back
    EV << "socket.sendTo, remoteAddress:" << remoteAddress << ", srcPort:" << srcPort << endl;
    socket.sendTo(pkt, remoteAddress, srcPort);
    msgLength = pkt->getByteLength();
    //makeSendPacket(remoteAddress, srcPort, msgLength, counter);
    //delete pkt;

#if 1
    // reSendTimeout
    //pkt_to = pkt->dup();//test
    if (reSendTimeout()) {
        remoteAddressTo = remoteAddress;
        srcPortTo = srcPort;
    } else {
        //delete pkt_to;
    }
#endif
    EV << "UdpEchoApp::sendEcho exit" << endl;
}

void UdpEchoAppDelay::makeSendPacket(L3Address destAddr, int destPort, int len, int numSent)
{
    Packet *packet = new Packet("AppPkt");
    packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(len));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    socket.sendTo(packet, destAddr, destPort);
}

} // namespace inet

