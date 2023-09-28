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
#include "inet/applications/udpapp/UdpEchoAppDelayNext.h"
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

Define_Module(UdpEchoAppDelayNext);

UdpEchoAppDelayNext::~UdpEchoAppDelayNext()
{
    cancelAndDelete(reSendTo);
}

void UdpEchoAppDelayNext::initialize(int stage)
{
    UdpEchoApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        reSendTo = new cMessage("Re-Send timeout");
        notifyNextPort = par("nextPort");
        packetName = par("packetName");
    } else if (stage == INITSTAGE_APPLICATION_LAYER) {
    
    // Subscribe to l2DisassociatedSignal to detect when connection 
    // with an AP is lost. The authentication process must be 
    // reset in such cases. 
    host = getContainingNode(this);
    host->subscribe(l2DisassociatedSignal, this);
    
    // Find the InterfaceTable entry for wlan0
    auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
    auto interfaceName = "wlan0"; // fixed interface for response
    cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
    for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            ie = interfaceTable->getInterface(i);
            if (interfaceMatcher.matches(ie->getInterfaceName())){
                break;
            }
        }
    }
}

void UdpEchoAppDelayNext::handleMessageWhenUp(cMessage *msg)
{
    EV << "[UdpEchoAppDelayNext::handleMessageWhenUp]" << endl;

    if (msg->isSelfMessage()){
        EV_DEBUG << "[UdpEchoAppDelayNext::handleMessageWhenUp] self message: type=" << msg->getKind() << endl;
        if (msg->getKind() == RE_SEND_TIMEOUT && isResend) {
            // re-send packet
            makeSendPacket(remoteAddressTo, srcPortTo, msgLength, numPacketsEchoed);
            scheduleResend();
        } else
            socket.processMessage(msg);
    }
    else
        socket.processMessage(msg);
}

void UdpEchoAppDelayNext::socketDataArrived(UdpSocket *socket, Packet *pk)
{
    EV << "[UdpEchoAppDelay::socketDataArrived]" << endl;

    if (pk->isSelfMessage()){
        isResend = false;
        cancelEvent(reSendTo);
        sendEcho(pk);
    } else {
        double delay = par("delayTime");
        if (delay >= 0) {
            EV_DEBUG << "[UdpEchoAppDelay::socketDataArrived] Packet transmission scheduled for time " << simTime() + delay;
            scheduleAt(simTime() + delay, pk);
        } else {
            EV << "[UdpEchoAppDelay::socketDataArrived] No more packet to echo back" << endl;
        }
    }
}

bool UdpEchoAppDelayNext::scheduleResend()
{
    EV << "[UdpEchoAppDelayNext::scheduleResend]" << endl;
    double timeOut = par("reSendTimeout");
    if (timeOut <= 0.0) {
        // If reSendTimeout is negative, do not schedule a resend
        return false;
    }
    else {
        cancelEvent(reSendTo);
        reSendTo->setKind(RE_SEND_TIMEOUT);
        scheduleAt(simTime() + timeOut, reSendTo);
        isResend = true;
        return true;
    }
}

void UdpEchoAppDelayNext::sendEcho(Packet *pkt)
{
    EV_DEBUG << "[UdpEchoAppDelayNext::sendEcho]" << endl;

    if (!isResend) {
        // Set sequence number
        auto bytesChunk = pkt->peekDataAsBytes();
        int seqId = bytesChunk->getByte(0);

        if (numPacketsEchoed < seqId) {
            EV << "[UdpEchoAppDelayNext::sendEcho] Discarding a message because numPacketsEchoed < seqId" << endl;
            return;
        }        
    }
    
    int numPacketsToEcho = par("count");
    if (numPacketsEchoed >= numPacketsToEcho) {
        EV << "[UdpEchoAppDelayNext::sendEcho] Already sent " << numPacketsToEcho << " packets. Proceeding to the next phase of authentication." << endl;
        cancelEvent(reSendTo);

        auto macAddr = ie->getMacAddress();
        std::ostringstream str;
        str << "[01]SendUDPFinish(" << macAddr << ")";
        recordScalar(str.str().c_str(), simTime());

        // Initiate the next phase of authentication
        if (notifyNextPort) {
            L3Address nextDestAddress("127.0.0.1");
            int nextDestPort = pkt->getTag<L4PortInd>()->getSrcPort() + 1;
            pkt->clearTags();
            pkt->trim();
            socket.sendTo(pkt, nextDestAddress, nextDestPort);
        }
    } else {
        // Echo back another packet to a remote server
        L3Address remoteAddress = pkt->getTag<L3AddressInd>()->getSrcAddress();
        int srcPort = pkt->getTag<L4PortInd>()->getSrcPort();
        int remotePortSameAsLocal = par("remotePortSameAsLocal");
        if (remotePortSameAsLocal) {
            srcPort = pkt->getTag<L4PortInd>()->getDestPort(); // fixed remote port is local port
        }
        const char * svr = par("remoteSvrAddr");
        if ( 0 != strlen(svr) ) {
            const char *destAddr = par("remoteSvrAddr");
            L3Address result;
            L3AddressResolver().tryResolve(destAddr, result);
            if (result.isUnspecified()) {
                EV_ERROR << "[UdpEchoAppDelayNext::sendEcho] Cannot resolve the destination address: " << destAddr << endl;
            } else {
                remoteAddress = result;
            }
        }
        pkt->clearTags();
        pkt->trim();
        pkt->setName(packetName);
        socket.sendTo(pkt, remoteAddress, srcPort);

        numPacketsEchoed++;
        EV << "[UdpEchoAppDelayNext::sendEcho] Sent " << numPacketsEchoed << " packet(s) so far." << endl;

        numEchoed++;  // Total number of packets echoed
        emit(packetSentSignal, pkt);
        
        msgLength = pkt->getByteLength();

        if (scheduleResend()) {
            remoteAddressTo = remoteAddress;
            srcPortTo = srcPort;
        }
    }
}

void UdpEchoAppDelayNext::makeSendPacket(L3Address destAddr, int destPort, int len, int numSent)
{
    Packet *packet = new Packet("re-send");
    packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(len));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    socket.sendTo(packet, destAddr, destPort);
}

void UdpEchoAppDelayNext::receiveSignal(cComponent *source, int signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();
    printSignalBanner(signalID, obj, details);

    // host associated. link is up. change the state to init.
    if (signalID == l2DisassociatedSignal) {
        InterfaceEntry *associatedIE = check_and_cast_nullable<InterfaceEntry *>(obj);
        if (associatedIE && ie == associatedIE) {
            EV_INFO << "[UdpEchoAppDelayNext::receiveSignal] Disassociated from AP. Resetting authentication status." << endl;
            isResend = false;
            cancelEvent(reSendTo);
            numPacketsEchoed = 0;
        }
    }
}

} // namespace inet

