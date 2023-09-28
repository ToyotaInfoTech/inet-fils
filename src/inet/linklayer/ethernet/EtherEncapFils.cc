/*
 * Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
 * Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
 * 
 * This program is based on "src/inet/linklayer/ethernet/EtherEncap.cc".
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "inet/applications/common/SocketTag_m.h"
#include "inet/common/INETUtils.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/EthernetCRC.h"
#include "inet/linklayer/common/FcsMode_m.h"
#include "inet/linklayer/common/Ieee802Ctrl.h"
#include "inet/linklayer/common/Ieee802SapTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/common/VlanTag_m.h"
#include "inet/linklayer/ethernet/EtherEncapFils.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/linklayer/ethernet/EthernetCommand_m.h"
#include "inet/linklayer/ethernet/EtherPhyFrame_m.h"
#include "inet/linklayer/ieee8022/Ieee8022LlcHeader_m.h"
#include "inet/networklayer/contract/IInterfaceTable.h"

namespace inet {

Define_Module(EtherEncapFils);

simsignal_t EtherEncapFils::encapPkSignal = registerSignal("encapPk");
simsignal_t EtherEncapFils::decapPkSignal = registerSignal("decapPk");
simsignal_t EtherEncapFils::pauseSentSignal = registerSignal("pauseSent");

EtherEncapFils::~EtherEncapFils()
{
    for (auto it : socketIdToSocketMap)
        delete it.second;
}

bool EtherEncapFils::Socket::matches(Packet *packet, const Ptr<const EthernetMacHeader>& ethernetMacHeader)
{
    if (!sourceAddress.isUnspecified() && !ethernetMacHeader->getSrc().isBroadcast() && ethernetMacHeader->getSrc() != sourceAddress)
        return false;
    if (!destinationAddress.isUnspecified() && !ethernetMacHeader->getDest().isBroadcast() && ethernetMacHeader->getDest() != destinationAddress)
        return false;
    if (protocol != nullptr && packet->getTag<PacketProtocolTag>()->getProtocol() != protocol)
        return false;
    if (vlanId != -1 && packet->getTag<VlanInd>()->getVlanId() != vlanId)
        return false;
    return true;
}

void EtherEncapFils::initialize(int stage)
{
    Ieee8022Llc::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        fcsMode = parseFcsMode(par("fcsMode"));
        seqNum = 0;
        WATCH(seqNum);
        totalFromHigherLayer = totalFromMAC = totalPauseSent = 0;
        useSNAP = par("useSNAP");
        WATCH(totalFromHigherLayer);
        WATCH(totalFromMAC);
        WATCH(totalPauseSent);
    }
    else if (stage == INITSTAGE_LINK_LAYER)
    {
        if (par("registerProtocol").boolValue()) {    //FIXME //KUDGE should redesign place of EtherEncap and LLC modules
            //register service and protocol
            registerService(Protocol::ethernetMac, gate("upperLayerIn"), nullptr);
            registerProtocol(Protocol::ethernetMac, nullptr, gate("upperLayerOut"));
        }
    }
}

void EtherEncapFils::processCommandFromHigherLayer(Request *msg)
{
    auto ctrl = msg->getControlInfo();
    if (dynamic_cast<Ieee802PauseCommand *>(ctrl) != nullptr)
        handleSendPause(msg);
    else if (auto bindCommand = dynamic_cast<EthernetBindCommand *>(ctrl)) {
        int socketId = check_and_cast<Request *>(msg)->getTag<SocketReq>()->getSocketId();
        Socket *socket = new Socket(socketId);
        socket->sourceAddress = bindCommand->getSourceAddress();
        socket->destinationAddress = bindCommand->getDestinationAddress();
        socket->protocol = bindCommand->getProtocol();
        socket->vlanId = bindCommand->getVlanId();
        socketIdToSocketMap[socketId] = socket;
        delete msg;
    }
    else if (dynamic_cast<EthernetCloseCommand *>(ctrl) != nullptr) {
        int socketId = check_and_cast<Request *>(msg)->getTag<SocketReq>()->getSocketId();
        auto it = socketIdToSocketMap.find(socketId);
        delete it->second;
        socketIdToSocketMap.erase(it);
        delete msg;
        auto indication = new Indication("closed", ETHERNET_I_SOCKET_CLOSED);
        auto ctrl = new EthernetSocketClosedIndication();
        indication->setControlInfo(ctrl);
        indication->addTag<SocketInd>()->setSocketId(socketId);
        send(indication, "transportOut");
    }
    else if (dynamic_cast<EthernetDestroyCommand *>(ctrl) != nullptr) {
        int socketId = check_and_cast<Request *>(msg)->getTag<SocketReq>()->getSocketId();
        auto it = socketIdToSocketMap.find(socketId);
        delete it->second;
        socketIdToSocketMap.erase(it);
        delete msg;
    }
    else
        Ieee8022Llc::processCommandFromHigherLayer(msg);
}

void EtherEncapFils::refreshDisplay() const
{
    Ieee8022Llc::refreshDisplay();
    char buf[80];
    sprintf(buf, "passed up: %ld\nsent: %ld", totalFromMAC, totalFromHigherLayer);
    getDisplayString().setTagArg("t", 0, buf);
}

void EtherEncapFils::processPacketFromHigherLayer(Packet *packet)
{
    delete packet->removeTagIfPresent<DispatchProtocolReq>();
    if (packet->getDataLength() > MAX_ETHERNET_DATA_BYTES)
        throw cRuntimeError("packet length from higher layer (%s) exceeds maximum Ethernet payload length (%s)", packet->getDataLength().str().c_str(), MAX_ETHERNET_DATA_BYTES.str().c_str());

    totalFromHigherLayer++;
    emit(encapPkSignal, packet);

    // Creates MAC header information and encapsulates received higher layer data
    // with this information and transmits resultant frame to lower layer

    // create Ethernet frame, fill it in from Ieee802Ctrl and encapsulate msg in it
    EV_DETAIL << "FILS Encapsulating higher layer packet `" << packet->getName() << "' for MAC\n";

    EV << "pkt:" << packet << endl;

    int typeOrLength = -1;
    if (!useSNAP) {
        auto protocolTag = packet->findTag<PacketProtocolTag>();
        if (protocolTag) {
            const Protocol *protocol = protocolTag->getProtocol();
            if (protocol) {
                int ethType = ProtocolGroup::ethertype.findProtocolNumber(protocol);
                if (ethType != -1)
                    typeOrLength = ethType;
            }
        }
    }
    EV << "pkt2:typeOrLength:" << typeOrLength << endl;
#if 1 //FILS step2
    if (typeOrLength != -1) { //packets between AP(app) and eth0
        auto macAddressReq = packet->getTag<MacAddressReq>();
        const auto& ethHeader = makeShared<EthernetMacHeader>();
        ethHeader->setSrc(macAddressReq->getSrcAddress());    // if blank, will be filled in by MAC
        ethHeader->setDest(macAddressReq->getDestAddress());
        ethHeader->setTypeOrLength(typeOrLength);
        packet->insertAtFront(ethHeader);
        packet->insertAtBack(makeShared<EthernetFcs>(fcsMode));
        packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);
    } else {
        //packets between STA and eth0 (not remove EthernetMacHeader)
    }
#else
    if (typeOrLength == -1) {
        Ieee8022Llc::encapsulate(packet);
        typeOrLength = packet->getByteLength();
    }
    auto macAddressReq = packet->getTag<MacAddressReq>();
    const auto& ethHeader = makeShared<EthernetMacHeader>();
    ethHeader->setSrc(macAddressReq->getSrcAddress());    // if blank, will be filled in by MAC
    ethHeader->setDest(macAddressReq->getDestAddress());
    ethHeader->setTypeOrLength(typeOrLength);
    packet->insertAtFront(ethHeader);

    packet->insertAtBack(makeShared<EthernetFcs>(fcsMode));

    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);
#endif
    EV_INFO << "Sending " << packet << " to lower layer.\n";
    send(packet, "lowerLayerOut");
}

const Ptr<const EthernetMacHeader> EtherEncapFils::decapsulateMacHeader(Packet *packet)
{
    auto ethHeader = packet->popAtFront<EthernetMacHeader>();
    packet->popAtBack<EthernetFcs>(ETHER_FCS_BYTES);

    // add Ieee802Ctrl to packet
    auto macAddressInd = packet->addTagIfAbsent<MacAddressInd>();
    macAddressInd->setSrcAddress(ethHeader->getSrc());
    macAddressInd->setDestAddress(ethHeader->getDest());

    // remove Padding if possible
    if (isIeee8023Header(*ethHeader)) {
        b payloadLength = B(ethHeader->getTypeOrLength());
        if (packet->getDataLength() < payloadLength)
            throw cRuntimeError("incorrect payload length in ethernet frame");
        packet->setBackOffset(packet->getFrontOffset() + payloadLength);
        packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ieee8022);
    }
    else if (isEth2Header(*ethHeader)) {
        if (auto protocol = ProtocolGroup::ethertype.findProtocol(ethHeader->getTypeOrLength()))
            packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(protocol);
        else
            packet->removeTagIfPresent<PacketProtocolTag>();
    }
    return ethHeader;
}

void EtherEncapFils::processPacketFromMac(Packet *packet)
{
    EV << "EtherEncap::processPacketFromMac:" << packet << endl;
#if 1 //FILS step2 STA<->eth_node: send wlan0 directly
    const auto& ethHeaderTemp = packet->peekAtFront<EthernetMacHeader>();
    if (nullptr == interfaceEntry) {
        //get my MacAddress
        auto interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        auto interfaceName = "eth0"; // fixed interface for response
        //getInterfaceId of eth0
        cPatternMatcher interfaceMatcher(interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            interfaceEntry = interfaceTable->getInterface(i);
            if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                break;
            }
        }
    }
    EV << "my:" << interfaceEntry->getMacAddress() << ", dest:" << ethHeaderTemp->getDest() << ", src:"<< ethHeaderTemp->getSrc() << endl;
#if 0 // in case of AP<->router<->eth_node
    packet->addTagIfAbsent<MacAddressReq>();
    if (packet->getTag<MacAddressReq>()->getDestAddress().isUnspecified()) {
        EV << "Add Tag<MacAddressReq>, set destAddr" << endl;
        packet->getTag<MacAddressReq>()->setDestAddress(ethHeaderTemp->getDest());
    }
#endif
    auto& destAddr = ethHeaderTemp->getDest();
    auto& srcAddr = ethHeaderTemp->getSrc();
    if (    (!(destAddr.equals(MacAddress::BROADCAST_ADDRESS)))
            && (!(destAddr.equals(interfaceEntry->getMacAddress()))) ) { //dest is not eth0
        //EthernetMacHeader in front
        send(packet, "upperLayerOut");//send to RelayUnit -> wlan0
        return;
    }
    //routing:remove EthernetMacHeader and send to ipv4 -> wlan0 -> STA
#endif
    const Protocol *payloadProtocol = nullptr;
    auto ethHeader = decapsulateMacHeader(packet);
    EV << "after decapsulateMacHeader:" << "ethHeader->getDest():" << ethHeader->getDest() << endl;
    // remove llc header if possible
    if (isIeee8023Header(*ethHeader)) {
        Ieee8022Llc::processPacketFromMac(packet);
        EV << "2:EtherEncap::processPack//etFromMac:" << endl;
        return;
    }
    else if (isEth2Header(*ethHeader)) {
        payloadProtocol = ProtocolGroup::ethertype.findProtocol(ethHeader->getTypeOrLength());
        if (payloadProtocol != nullptr) {
            packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(payloadProtocol);
            packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(payloadProtocol);
        }
        else {
            packet->removeTagIfPresent<PacketProtocolTag>();
            packet->removeTagIfPresent<DispatchProtocolReq>();
        }
        bool stealPacket = false;
        for (auto it : socketIdToSocketMap) {
            auto socket = it.second;
            if (socket->matches(packet, ethHeader)) {
                auto packetCopy = packet->dup();
                packetCopy->setKind(ETHERNET_I_DATA);
                packetCopy->addTagIfAbsent<SocketInd>()->setSocketId(it.first);
                EV << "3:EtherEncap::processPacketFromMac:" << endl;
                send(packetCopy, "upperLayerOut");
                stealPacket |= socket->vlanId != -1;
            }
        }
        // TODO: should the socket configure if it steals packets or not?
        if (stealPacket) {
            EV << "3:EtherEncap::processPacketFromMac:" << endl;
            delete packet;
        } else if (payloadProtocol != nullptr && upperProtocols.find(payloadProtocol) != upperProtocols.end()) {
            EV_DETAIL << "Decapsulating frame `" << packet->getName() << "', passing up contained packet `"
                      << packet->getName() << "' to higher layer\n";

            totalFromMAC++;
            emit(decapPkSignal, packet);

            // pass up to higher layers.
            EV_INFO << "Sending " << packet << " to upper layer.\n";

            send(packet, "upperLayerOut");
        }
        else {
            EV_WARN << "Unknown protocol, dropping packet\n";
            PacketDropDetails details;
            details.setReason(NO_PROTOCOL_FOUND);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
        }
    }
    else
        throw cRuntimeError("Unknown ethernet header");
}

void EtherEncapFils::handleSendPause(cMessage *msg)
{
    Ieee802PauseCommand *etherctrl = dynamic_cast<Ieee802PauseCommand *>(msg->getControlInfo());
    if (!etherctrl)
        throw cRuntimeError("PAUSE command `%s' from higher layer received without Ieee802PauseCommand controlinfo", msg->getName());
    MacAddress dest = etherctrl->getDestinationAddress();
    int pauseUnits = etherctrl->getPauseUnits();
    delete msg;

    EV_DETAIL << "Creating and sending PAUSE frame, with duration = " << pauseUnits << " units\n";

    // create Ethernet frame
    char framename[40];
    sprintf(framename, "pause-%d-%d", getId(), seqNum++);
    auto packet = new Packet(framename);
    const auto& frame = makeShared<EthernetPauseFrame>();
    const auto& hdr = makeShared<EthernetMacHeader>();
    frame->setPauseTime(pauseUnits);
    if (dest.isUnspecified())
        dest = MacAddress::MULTICAST_PAUSE_ADDRESS;
    hdr->setDest(dest);
    packet->insertAtFront(frame);
    hdr->setTypeOrLength(ETHERTYPE_FLOW_CONTROL);
    packet->insertAtFront(hdr);
    packet->insertAtBack(makeShared<EthernetFcs>(fcsMode));
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);

    EV_INFO << "Sending " << frame << " to lower layer.\n";
    send(packet, "lowerLayerOut");

    emit(pauseSentSignal, pauseUnits);
    totalPauseSent++;
}

} // namespace inet

