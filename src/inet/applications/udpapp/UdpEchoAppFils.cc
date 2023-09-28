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
#include "inet/applications/udpapp/UdpEchoAppFils.h"
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

//FILS
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/applications/common/SocketTag_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211SubtypeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/linklayer/common/MacAddressTag_m.h"

namespace inet {

Define_Module(UdpEchoAppFils);

void UdpEchoAppFils::initialize(int stage)
{
    UdpEchoApp::initialize(stage);

    //par
    authSvrPort = par("authSvrPort");
    dhcpSvrPort = par("dhcpSvrPort");
    authMessageLength = par("authMessageLength");
    dhcpMessageLength = par("dhcpMessageLength");
}

void UdpEchoAppFils::handleMessageWhenUp(cMessage *msg)
{
    if (interfaceId == -1) {
        //getInterfaceId
        auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        auto interfaceName = "wlan0"; // fixed interface for response
        InterfaceEntry* interfaceEntry;
        cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            interfaceEntry = interfaceTable->getInterface(i);
            if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                break;
            }
        }
        if (interfaceEntry) {
            interfaceId = interfaceEntry->getInterfaceId();
        } else {
            throw cRuntimeError("UdpEchoAppFils::handleMessageWhenUp Can not get Interface id (wlan0)");
        }
    }
    socket.processMessage(msg);
}

void UdpEchoAppFils::socketDataArrived(UdpSocket *socket, Packet *pk)
{
    // determine its source address
    L3Address srcAddress = pk->getTag<L3AddressInd>()->getSrcAddress();
    // statistics
    numEchoed++;
    emit(packetSentSignal, pk);

    /* get from echo packet */
    int subType;
    MacAddress destMacAddr;
    if ( pk->findTag<Ieee80211SubtypeReq>() ) {
        subType = pk->getTag<Ieee80211SubtypeReq>()->getSubtype();
        destMacAddr = pk->getTag<MacAddressReq>()->getDestAddress();
    }
    pk->clearTags();
    pk->trim();

    /* send packet */
    L3Address addrLo("127.0.0.1");//from AP wlan
    int length;//byte length
    //select action by srcAddress
    const auto& header = makeShared<ieee80211::Ieee80211MgmtHeader>();
    if (srcAddress.toIpv4() == addrLo.toIpv4()){
        EV << "UDP packet from addrLo(wlan), pk:" << pk << "\n";
        switch ( subType ) {
            case ieee80211::ST_FILS_AUTH_REQ:
                //Auth Req
                //set subType and destMacAddr in Ieee80211MgmtHeader
                header->setTransmitterAddress(destMacAddr);
                EV << "destMacAddr" << destMacAddr << "\n";
                header->setType(0, 0, subType);//read: getFrameType()<<4) | getSubType()
                pk->insertAtFront(header);//without Ieee80211MacTrailer
                length = pk->getByteLength();
                if ( length < authMessageLength) {
                    auto rawBytesData = makeShared<ByteCountChunk>(B(authMessageLength - length), 0);
                    pk->insertAtBack(rawBytesData);
                }
                authSvrAddr = L3AddressResolver().resolve(par("authSvrAddr"));
                EV << "AUTH_REQ send remote:" << authSvrAddr << " port:" << authSvrPort << "\n";
                socket->sendTo(pk, authSvrAddr, authSvrPort);
                return;
                break;

            case ieee80211::ST_FILS_ASSOC_REQ:
                //DHCP Req
                //set subType and destMacAddr in Ieee80211MgmtHeader
                header->setTransmitterAddress(destMacAddr);
                EV << "destMacAddr" << destMacAddr << "\n";
                header->setType(0, 0, subType);//read: getFrameType()<<4) | getSubType()
                pk->insertAtFront(header);//without Ieee80211MacTrailer
                length = pk->getByteLength();
                if ( length < dhcpMessageLength) {
                    auto rawBytesData = makeShared<ByteCountChunk>(B(dhcpMessageLength - length), 0);
                    pk->insertAtBack(rawBytesData);
                }
                dhcpSvrAddr = L3AddressResolver().resolve(par("dhcpSvrAddr"));
                EV << "ASSOC_REQ send remote:" << dhcpSvrAddr << "\n";
                socket->sendTo(pk, dhcpSvrAddr, dhcpSvrPort);
                return;
                break;
            default:
                EV << "unsupported subType:" << subType << "\n";
                return;
                break;
        }
    } else {
        EV << "UDP packet from eth0, pk:" << pk << "\n";
        auto mgmtHeader = pk->peekAtFront<ieee80211::Ieee80211MgmtHeader>();
        //subType contains getFrameType and getSubType
        auto subType = ((mgmtHeader->getFrameType()) << 4) | mgmtHeader->getSubType();
        pk->addTagIfAbsent<Ieee80211SubtypeReq>()->setSubtype(subType);
        pk->addTagIfAbsent<MacAddressReq>()->setDestAddress(mgmtHeader->getTransmitterAddress());
        EV << "destMacAddr" << mgmtHeader->getTransmitterAddress() << "\n";
        switch ( subType ) {
             case ieee80211::ST_FILS_AUTH_REQ:
                 //Auth Resp
                 pk->setName("Auth-Resp");
                 pk->addTagIfAbsent<Ieee80211SubtypeReq>()->setSubtype(ieee80211::ST_FILS_AUTH_RESP);
                 break;

             case ieee80211::ST_FILS_ASSOC_REQ:
                 pk->setName("Assoc-Resp");
                 pk->addTagIfAbsent<Ieee80211SubtypeReq>()->setSubtype(ieee80211::ST_FILS_ASSOC_RESP);
                 break;

             default:
                 EV << "unsupported subType:" << subType << "\n";
                 break;
        }
        //reply to wlan0
        pk->removeTagIfPresent<SocketInd>();
        pk->removeTagIfPresent<DispatchProtocolReq>();
        pk->removeTagIfPresent<PacketProtocolTag>();
        if (interfaceId != -1) {
            pk->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interfaceId);
        } else {
            throw cRuntimeError("UdpEchoAppFils::socketDataArrived Can not get Interface id (wlan0)");
        }
        send(pk, "socketOut");//send to dispatcher
    }
}

} // namespace inet

