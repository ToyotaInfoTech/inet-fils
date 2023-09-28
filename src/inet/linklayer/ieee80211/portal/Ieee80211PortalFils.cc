//
// Copyright (C) OpenSim Ltd.
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is based on "src/inet/linklayer/ieee80211/portal/Ieee80211Portal.cc".
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
// along with this program; if not, see http://www.gnu.org/licenses/.
//

#include "inet/common/INETDefs.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/linklayer/common/FcsMode_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"

#ifdef WITH_ETHERNET
#include "inet/linklayer/ethernet/EtherEncapFils.h"
#include "inet/linklayer/ethernet/EtherPhyFrame_m.h"
#endif // ifdef WITH_ETHERNET

#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/linklayer/ieee80211/portal/Ieee80211PortalFils.h"
#include "inet/linklayer/ieee8022/Ieee8022LlcHeader_m.h"

//FILS
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211SubtypeTag_m.h"
#include "inet/linklayer/ieee80211/mgmt/Ieee80211MgmtAp.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/common/checksum/TcpIpChecksum.h"
#include "inet/transportlayer/udp/Udp.h"
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/contract/IInterfaceTable.h"

namespace inet {

namespace ieee80211 {

Define_Module(Ieee80211PortalFils);

void Ieee80211PortalFils::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        upperLayerOutConnected = gate("upperLayerOut")->getPathEndGate()->isConnected();
#ifdef WITH_ETHERNET
        fcsMode = parseFcsMode(par("fcsMode"));
#endif // ifdef WITH_ETHERNET
    }
}

void Ieee80211PortalFils::handleMessage(cMessage *message)
{
    EV << "Ieee80211Portal::handleMessage\n";
    if (message->arrivedOn("upperLayerIn")) {
        auto packet = check_and_cast<Packet *>(message);
        if ( packet->findTag<Ieee80211SubtypeReq>() ) {
            auto subType = (Ieee80211FrameType)packet->getTag<Ieee80211SubtypeReq>()->getSubtype();
            if ( (ST_FILS_AUTH_RESP == subType) || (ST_FILS_ASSOC_RESP == subType) ) {
                // FILS
                send(message, "lowerLayerOut");
                return;
            }
        }
        encapsulate(packet);
        send(packet, "lowerLayerOut");
        return;
    }
    else if (message->arrivedOn("lowerLayerIn")) {
        auto packet = check_and_cast<Packet *>(message);
        if ( packet->findTag<Ieee80211SubtypeReq>() ) {
            auto subType = (Ieee80211FrameType)packet->getTag<Ieee80211SubtypeReq>()->getSubtype();
            if ( (ST_FILS_AUTH_REQ == subType) || (ST_FILS_ASSOC_REQ == subType) ) {
                // FILS
                filsDecapsulate(packet);
            } else {
                decapsulate(packet);
            }
        } else {
            decapsulate(packet);
        }
        if (upperLayerOutConnected)
            send(packet, "upperLayerOut");
        else
            delete packet;
    }
    else
        throw cRuntimeError("Unknown message");
}

void Ieee80211PortalFils::encapsulate(Packet *packet)
{
    EV << "Ieee80211Portal::encapsulate:" << packet->getFullName() << ", packet:" << packet << endl;
#ifdef WITH_ETHERNET
#if 1
    if ((packet->getByteLength() != 64) && (packet->getByteLength() != 346)){ //not arpREPLY / FILS step2 no EthernetMacHeader
        EV << "noEthMacHdr" << endl;
        const auto& ieee8022SnapHeader = makeShared<Ieee8022LlcSnapHeader>();
        ieee8022SnapHeader->setOui(0);
        if (28 == packet->getByteLength() ) {
            ieee8022SnapHeader->setProtocolId(ETHERTYPE_ARP);
        } else {
            ieee8022SnapHeader->setProtocolId(ETHERTYPE_IPv4);
        }
        EV << "etherType:" << ieee8022SnapHeader->getProtocolId() << endl;
        packet->insertAtFront(ieee8022SnapHeader);
        packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ieee8022);
        EV << "set packet:" << packet << endl;
        return;
    }
#endif
    EV << "before decapsulateMacHeader:" << packet << endl;
    auto ethernetHeader = EtherEncapFils::decapsulateMacHeader(packet);       // do not use const auto& : trimChunks() delete it from packet
    packet->trim();
    packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(ethernetHeader->getDest());
    EV << "dest:" << ethernetHeader->getDest() << endl;
    packet->addTagIfAbsent<MacAddressReq>()->setSrcAddress(ethernetHeader->getSrc());
    if (isIeee8023Header(*ethernetHeader))
        // check that the packet already has an LLC header
        packet->peekAtFront<Ieee8022LlcHeader>();
    else if (isEth2Header(*ethernetHeader)){
        const auto& ieee8022SnapHeader = makeShared<Ieee8022LlcSnapHeader>();
        ieee8022SnapHeader->setOui(0);
        ieee8022SnapHeader->setProtocolId(ethernetHeader->getTypeOrLength());
        packet->insertAtFront(ieee8022SnapHeader);
        packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ieee8022);
    }
    else
        throw cRuntimeError("Unknown packet: '%s'", packet->getFullName());
#else // ifdef WITH_ETHERNET
    throw cRuntimeError("INET compiled without ETHERNET feature!");
#endif // ifdef WITH_ETHERNET
}

void Ieee80211PortalFils::decapsulate(Packet *packet)
{
    EV << "Ieee80211Portal::decapsulate\n";
#ifdef WITH_ETHERNET
    packet->trim();
    int typeOrLength = packet->getByteLength();
    const auto& llcHeader = packet->peekAtFront<Ieee8022LlcHeader>();
    if (llcHeader->getSsap() == 0xAA && llcHeader->getDsap() == 0xAA && llcHeader->getControl() == 0x03) {
        const auto& snapHeader = dynamicPtrCast<const Ieee8022LlcSnapHeader>(llcHeader);
        if (snapHeader == nullptr)
            throw cRuntimeError("LLC header indicates SNAP header, but SNAP header is missing");
        if (snapHeader->getOui() == 0) {
            // snap header with ethertype
            typeOrLength = snapHeader->getProtocolId();
            packet->eraseAtFront(snapHeader->getChunkLength());
        }
    }
#if 1 //FILS step2
    //getInterfaceEntry of wlan0
    if (nullptr == interfaceEntry) {
        auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        auto interfaceName = "wlan0"; // fixed interface for response
        cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            interfaceEntry = interfaceTable->getInterface(i);
            if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                break;
            }
        }
    }
    //dest macAddr is wlan0
    if (nullptr != interfaceEntry) {
        EV << "interfaceEntry is not null" << endl;
    }
    EV << "wlan0_mac:" << interfaceEntry->getMacAddress();
    EV << ", dest:" << packet->getTag<MacAddressInd>()->getDestAddress() << endl;
    if (nullptr != interfaceEntry
            && interfaceEntry->getMacAddress().equals(packet->getTag<MacAddressInd>()->getDestAddress()) ) {
        EV << "set protocol:send to ip4 node in AP" << endl;
        //send to ip4 node in AP
        packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::arp);
        packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::arp);
        packet->addTagIfAbsent<L3AddressReq>();
        return;
    }
#endif
    const auto& ethernetHeader = makeShared<EthernetMacHeader>();
    ethernetHeader->setSrc(packet->getTag<MacAddressInd>()->getSrcAddress());
    ethernetHeader->setDest(packet->getTag<MacAddressInd>()->getDestAddress());
    ethernetHeader->setTypeOrLength(typeOrLength);
    packet->insertAtFront(ethernetHeader);
    packet->insertAtBack(makeShared<EthernetFcs>(fcsMode));
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ethernetMac);
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);
#else // ifdef WITH_ETHERNET
    throw cRuntimeError("INET compiled without ETHERNET feature!");
#endif // ifdef WITH_ETHERNET
}

void Ieee80211PortalFils::filsDecapsulate(Packet *packet)
{
    EV << "Ieee80211Portal::filsDecapsulate\n";
#ifdef WITH_ETHERNET
    //pre process
    Chunk::enableImplicitChunkSerialization = true;//with no exception
    packet->trim();
    EV << "Ieee80211Portal::payload length:" << packet->getTotalLength() << "\n";

    //add udp header
    const auto& udpHeader = makeShared<UdpHeader>();
    udpHeader->setDestinationPort(par("appDestPort"));
    udpHeader->setTotalLengthField(udpHeader->getChunkLength() + packet->getTotalLength());
    //CRC
    udpHeader->setCrcMode(CRC_COMPUTED);
    auto src = new L3Address("127.0.0.1");//localhost
    auto dst = new L3Address("127.0.0.1");//localhost
    Udp::insertCrc(&Protocol::ipv4, src->toIpv4(), dst->toIpv4(), udpHeader, packet);

    packet->insertAtFront(udpHeader);
    EV << "1_Ieee80211Portal::with udpHeader length:" << packet->getTotalLength() << "\n";

    //add IP header
    const auto& ipv4Header = makeShared<Ipv4Header>();
    ipv4Header->setVersion(4);
    ipv4Header->setHeaderLength(IPv4_MIN_HEADER_LENGTH);
    ipv4Header->setProtocolId(IP_PROT_UDP);
    ipv4Header->setTimeToLive(32);
    ipv4Header->setMoreFragments(0);
    ipv4Header->setDontFragment(0);
    ipv4Header->setFragmentOffset(0);
    ipv4Header->setTypeOfService(0);
    ipv4Header->setChunkLength(IPv4_MIN_HEADER_LENGTH);
    ipv4Header->setSrcAddress(src->toIpv4());
    ipv4Header->setDestAddress(dst->toIpv4());
    ipv4Header->setIdentification(1);//tmp
    ipv4Header->setTotalLengthField(ipv4Header->getChunkLength() + packet->getTotalLength());
    //CRC setup
    ipv4Header->setCrcMode(CRC_COMPUTED);
    ipv4Header->setCrc(0);
    //calculation
    MemoryOutputStream ipv4HeaderStream;
    Chunk::serialize(ipv4HeaderStream, ipv4Header);
    uint16_t crc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
    ipv4Header->setCrc(crc);
    //set Tag
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<L3AddressReq>()->setSrcAddress(src->toIpv4());
    packet->addTagIfAbsent<L3AddressReq>()->setDestAddress(dst->toIpv4());

    packet->insertAtFront(ipv4Header);
    EV << "2_Ieee80211Portal::with IpHeader length:" << packet->getTotalLength() << "\n";

#else // ifdef WITH_ETHERNET
    throw cRuntimeError("INET compiled without ETHERNET feature!");
#endif // ifdef WITH_ETHERNET
}

} // namespace ieee80211

} // namespace inet

