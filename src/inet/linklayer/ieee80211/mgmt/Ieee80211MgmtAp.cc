//
// Copyright (C) 2006 Andras Varga
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
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

#include "inet/common/ModuleAccess.h"
#include "inet/common/Simsignals.h"
#include "inet/linklayer/common/MacAddressTag_m.h"

#ifdef WITH_ETHERNET
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/linklayer/ethernet/EtherEncap.h"
#endif // ifdef WITH_ETHERNET

#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211SubtypeTag_m.h"
#include "inet/linklayer/ieee80211/mgmt/Ieee80211MgmtAp.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211Radio.h"
#include "inet/physicallayer/contract/packetlevel/SignalTag_m.h"

#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"

namespace inet {

namespace ieee80211 {

using namespace physicallayer;

Define_Module(Ieee80211MgmtAp);
Register_Class(Ieee80211MgmtAp::NotificationInfoSta);

static std::ostream& operator<<(std::ostream& os, const Ieee80211MgmtAp::StaInfo& sta)
{
    os << "address:" << sta.address;
    return os;
}

Ieee80211MgmtAp::~Ieee80211MgmtAp()
{
    cancelAndDelete(beaconTimer);
    cancelAndDelete(filsDiscoveryTimer);
}

void Ieee80211MgmtAp::initialize(int stage)
{

    Ieee80211MgmtApBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // read params and init vars
        ssid = par("ssid").stdstringValue();
        beaconInterval = par("beaconInterval");
        filsDiscoveryInterval = par("filsDiscoveryInterval");
        numAuthSteps = par("numAuthSteps");
        if (numAuthSteps != 2 && numAuthSteps != 4)
            throw cRuntimeError("parameter 'numAuthSteps' (number of frames exchanged during authentication) must be 2 or 4, not %d", numAuthSteps);
        channelNumber = -1;    // value will arrive from physical layer in receiveChangeNotification()

        enableFils = par("enableFils");
        numUe = par("numUe");
        rsnGroupDataCipherSuite = par("rsnGroupDataCipherSuite");
        rsnPairwiseCipherSuiteCount = par("rsnPairwiseCipherSuiteCount");
        rsnPairwiseCipherSuiteList = par("rsnPairwiseCipherSuiteList");
        rsnAkmSuiteCount = par("rsnAkmSuiteCount");
        rsnAkmSuiteList = par("rsnAkmSuiteList");
        rsnCapabilities = par("rsnCapabilities");
        rsnPmkidCount = par("rsnPmkidCount");
        rsnPmkidList = par("rsnPmkidList");
        rsnGroupManagementCipherSuite = par("rsnGroupManagementCipherSuite");

        filsWrappedDataLen = par("filsWrappedDataLen");


        WATCH(ssid);
        WATCH(channelNumber);
        WATCH(beaconInterval);
        WATCH(filsDiscoveryInterval);
        WATCH(numAuthSteps);
        WATCH_MAP(staList);

        //TBD fill in supportedRates

        // subscribe for notifications
        cModule *radioModule = getModuleFromPar<cModule>(par("radioModule"), this);
        radioModule->subscribe(Ieee80211Radio::radioChannelChangedSignal, this);

        // get routing table of router
        if (strcmp(par("wifiRouterRoutingTableModule").stringValue(), "") != 0) {
            irt = getModuleFromPar<IIpv4RoutingTable>(par("wifiRouterRoutingTableModule"), this);
        }

        // start beacon timer (randomize startup time)
        beaconTimer = new cMessage("beaconTimer");
        // start FILS timer (randomize startup time)
        filsDiscoveryTimer = new cMessage("filsDiscoveryTimer");
    }
}

void Ieee80211MgmtAp::handleTimer(cMessage *msg)
{
    if (msg == beaconTimer) {
        sendBeacon();
        nextBeaconTime = simTime() + beaconInterval;
        scheduleAt(nextBeaconTime, beaconTimer);
    } else if (msg == filsDiscoveryTimer) {
        if (0 == enableFils) return;
        auto next_fd_time = simTime() + filsDiscoveryInterval;
        if (nextBeaconTime >  next_fd_time ) {
            sendFilsDiscovery();
        }
        scheduleAt(next_fd_time, filsDiscoveryTimer);
    }
    else {
        throw cRuntimeError("internal error: unrecognized timer '%s'", msg->getName());
    }
}

void Ieee80211MgmtAp::handleCommand(int msgkind, cObject *ctrl)
{
    throw cRuntimeError("handleCommand(): no commands supported");
}

void Ieee80211MgmtAp::receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details)
{
    Enter_Method_Silent();
    if (signalID == Ieee80211Radio::radioChannelChangedSignal) {
        EV << "updating channel number\n";
        channelNumber = value;
    }
}

Ieee80211MgmtAp::StaInfo *Ieee80211MgmtAp::lookupSenderSTA(const Ptr<const Ieee80211MgmtHeader>& header)
{
    auto it = staList.find(header->getTransmitterAddress());
    return it == staList.end() ? nullptr : &(it->second);
}

void Ieee80211MgmtAp::sendManagementFrame(const char *name, const Ptr<Ieee80211MgmtFrame>& body, int subtype, const MacAddress& destAddr)
{
    EV << "Ieee80211MgmtAp::sendManagementFrame:destAddr=" << destAddr << "\n";
    auto packet = new Packet(name);
    packet->addTag<MacAddressReq>()->setDestAddress(destAddr);
    packet->addTag<Ieee80211SubtypeReq>()->setSubtype(subtype);
    packet->insertAtBack(body);
    EV << "body:" << body << ", packet:" << packet << ", getTotalLength:" << packet->getTotalLength() << "\n";
    sendDown(packet);
}

void Ieee80211MgmtAp::sendBeacon()
{
    EV << "Sending beacon:enableFils:" << enableFils << "\n";
    const auto& body = makeShared<Ieee80211BeaconFrame>();

    body->setSSID(ssid.c_str());
    body->setSupportedRates(supportedRates);
    body->setBeaconInterval(beaconInterval);
    body->setChannelNumber(channelNumber);
    body->setChunkLength(B(8 + 2 + 2 + (2 + ssid.length()) + (2 + supportedRates.numRates)));

    /* FILS Indication element */
    body->setEnableFils(enableFils);
    body->setChunkLength(body->getChunkLength() + B(4));
    sendManagementFrame("Beacon", body, ST_BEACON, MacAddress::BROADCAST_ADDRESS);
  }

void Ieee80211MgmtAp::sendFilsDiscovery()
{
    if (1 != enableFils) return;
    EV << "sendFilsDiscovery()" << endl;
    const auto& body = makeShared<Ieee80211FilsDiscoveryFrame>();
    body->setSSID(ssid.c_str());
    body->setBeaconInterval(beaconInterval);
    body->setChunkLength(B(1 + 1 + 2 + 8 + 2 + (2 + ssid.length())));//Category, PublicAction, FilsDiscoveryInformationField
    sendManagementFrame("FILS Discovery", body, ST_ACTION, MacAddress::BROADCAST_ADDRESS);
}

void Ieee80211MgmtAp::handleFilsAuthReqFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    const auto& requestBody = packet->peekData<Ieee80211AuthenticationFrame>();
     int frameAuthSeq = requestBody->getSequenceNumber();
     EV << "handleFilsAuthReqFrame, seqNum=" << frameAuthSeq << "\n";
     EV << "AP:enableFils:" << enableFils << ", packet:" << packet << endl;
     // create STA entry if needed
     StaInfo *sta = lookupSenderSTA(header);
//     EV << "#########Auth=" << requestBody->getAuthTime() << "\n";
     sta->authTime = requestBody->getAuthTime();
     if (!sta) {
         MacAddress staAddress = header->getTransmitterAddress();
         sta = &staList[staAddress];    // this implicitly creates a new entry
         sta->address = staAddress;
         mib->bssAccessPointData.stations[staAddress] = Ieee80211Mib::NOT_AUTHENTICATED;
         sta->authSeqExpected = 1;
     }

     // reset authentication status, when starting a new auth sequence
     // The statements below are added because the L2 handover time was greater than before when
     // a STA wants to re-connect to an AP with which it was associated before. When the STA wants to
     // associate again with the previous AP, then since the AP is already having an entry of the STA
     // because of old association, and thus it is expecting an authentication frame number 3 but it
     // receives authentication frame number 1 from STA, which will cause the AP to return an Auth-Error
     // making the MN STA to start the handover process all over again.
     if (frameAuthSeq == 1) {
         if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
             sendDisAssocNotification(sta->address);
         mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::NOT_AUTHENTICATED;
         sta->authSeqExpected = 1;
     }

     // check authentication sequence number is OK
     if (frameAuthSeq != sta->authSeqExpected) {
         // wrong sequence number: send error and return
         EV << "Wrong sequence number, " << sta->authSeqExpected << " expected\n";
         const auto& body = makeShared<Ieee80211AuthenticationFrame>();
         body->setStatusCode(SC_AUTH_OUT_OF_SEQ);
         EV << "AP:enableFils:" << enableFils << ", sta->enableFils:" << sta->enableFils << endl;
         body->setEnableFils(enableFils & sta->enableFils);
         sendManagementFrame("Auth-ERROR", body, ST_AUTHENTICATION, header->getTransmitterAddress());
         delete packet;
         sta->authSeqExpected = 1;    // go back to start square
         return;
     }
     sta->frameAuthSeq = frameAuthSeq; //FILS backup

     // send FILS AUTH request
     EV << "Sending FILS_AUTH request frame from Mgmt" << "\n";
     const auto& body = makeShared<Ieee80211AuthenticationFrame>();
     sendManagementFrame("Auth-REQ", body, ST_FILS_AUTH_REQ, header->getTransmitterAddress());

     delete packet;
}

void Ieee80211MgmtAp::handleAuthenticationFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    const auto& requestBody = packet->peekData<Ieee80211AuthenticationFrame>();
    int frameAuthSeq = requestBody->getSequenceNumber();
    EV << "Processing Authentication frame, seqNum=" << frameAuthSeq << "\n";

    // create STA entry if needed
    StaInfo *sta = lookupSenderSTA(header);
    if (!sta) {
        MacAddress staAddress = header->getTransmitterAddress();
        sta = &staList[staAddress];    // this implicitly creates a new entry
        sta->address = staAddress;
        mib->bssAccessPointData.stations[staAddress] = Ieee80211Mib::NOT_AUTHENTICATED;
        sta->authSeqExpected = 1;
    }
    sta->authTime = requestBody->getAuthTime();
    //set wifiRouter
    setRoutingTable(sta->address, mib->address);
    //FILS
    if (requestBody->getEnableFils()) {
        sta->enableFils = 1;
    } else {
        sta->enableFils = 0;
    }
    EV << "AP:sta->enableFils:" << sta->enableFils << endl;
    if (enableFils & sta->enableFils) {
        handleFilsAuthReqFrame(packet, header);
        return;
    }

    // reset authentication status, when starting a new auth sequence
    // The statements below are added because the L2 handover time was greater than before when
    // a STA wants to re-connect to an AP with which it was associated before. When the STA wants to
    // associate again with the previous AP, then since the AP is already having an entry of the STA
    // because of old association, and thus it is expecting an authentication frame number 3 but it
    // receives authentication frame number 1 from STA, which will cause the AP to return an Auth-Error
    // making the MN STA to start the handover process all over again.
    if (frameAuthSeq == 1) {
        if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
            sendDisAssocNotification(sta->address);
        mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::NOT_AUTHENTICATED;
        sta->authSeqExpected = 1;
    }

    // check authentication sequence number is OK
    if (frameAuthSeq != sta->authSeqExpected) {
        // wrong sequence number: send error and return
        EV << "Wrong sequence number, " << sta->authSeqExpected << " expected\n";
        const auto& body = makeShared<Ieee80211AuthenticationFrame>();
        body->setStatusCode(SC_AUTH_OUT_OF_SEQ);
        sendManagementFrame("Auth-ERROR", body, ST_AUTHENTICATION, header->getTransmitterAddress());
        delete packet;
        sta->authSeqExpected = 1;    // go back to start square
        return;
    }

    // station is authenticated if it made it through the required number of steps
    bool isLast = (frameAuthSeq + 1 == numAuthSteps);

    // send OK response (we don't model the cryptography part, just assume
    // successful authentication every time)
    EV << "Sending Authentication frame, seqNum=" << (frameAuthSeq + 1) << "\n";
    const auto& body = makeShared<Ieee80211AuthenticationFrame>();
    body->setSequenceNumber(frameAuthSeq + 1);
    body->setStatusCode(SC_SUCCESSFUL);
    body->setIsLast(isLast);
    body->setEnableFils(enableFils & sta->enableFils);
    // XXX frame length could be increased to account for challenge text length etc.
    sendManagementFrame(isLast ? "Auth-OK" : "Auth", body, ST_AUTHENTICATION, header->getTransmitterAddress());

    delete packet;

    // update status
    if (isLast) {
        if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
            sendDisAssocNotification(sta->address);
        mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::AUTHENTICATED;    // XXX only when ACK of this frame arrives
        EV << "STA authenticated\n";
    }
    else {
        sta->authSeqExpected += 2;
        EV << "Expecting Authentication frame " << sta->authSeqExpected << "\n";
    }
}

void Ieee80211MgmtAp::handleFilsAuthRespFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Ieee80211MgmtAp::handleFilsAuthRespFrame\n";
    //const auto& requestBody = packet->peekData<Ieee80211AuthenticationFrame>();
    // STA entry is exist
    EV << "DestAddr:" << packet->getTag<MacAddressReq>()->getDestAddress() << "\n";
    StaInfo *sta = &staList[packet->getTag<MacAddressReq>()->getDestAddress()];
    if (!sta) {
        throw cRuntimeError("Ieee80211MgmtAp::handleFilsAuthRespFrame  not find STA");
    }
    int frameAuthSeq = sta->frameAuthSeq;//restore

    // station is authenticated if it made it through the required number of steps
    bool isLast = (frameAuthSeq + 1 == numAuthSteps);

    // send OK response (we don't model the cryptography part, just assume
    // successful authentication every time)
    EV << "Sending Authentication frame, seqNum=" << (frameAuthSeq + 1) << "\n";
    const auto& body = makeShared<Ieee80211AuthenticationFrame>();
    body->setSequenceNumber(frameAuthSeq + 1);
    body->setStatusCode(SC_SUCCESSFUL);
    body->setIsLast(isLast);
    EV << "AP:enableFils:" << enableFils << ", sta->enableFils:" << sta->enableFils << endl;
    body->setEnableFils(enableFils & sta->enableFils);
    // XXX frame length could be increased to account for challenge text length etc.
    body->setChunkLength(B(2 + 2 + 2 + 81 )); //81:FILS
    sendManagementFrame(isLast ? "Auth-OK" : "Auth", body, ST_AUTHENTICATION, header->getTransmitterAddress());

    delete packet;

    // update status
    if (isLast) {
        if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
            sendDisAssocNotification(sta->address);
        mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::AUTHENTICATED;    // XXX only when ACK of this frame arrives
        EV << "STA authenticated\n";
    }
    else {
        sta->authSeqExpected += 2;
        EV << "Expecting Authentication frame " << sta->authSeqExpected << "\n";
    }
}

void Ieee80211MgmtAp::handleDeauthenticationFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Processing Deauthentication frame\n";

    StaInfo *sta = lookupSenderSTA(header);
    delete packet;

    if (sta) {
        // mark STA as not authenticated; alternatively, it could also be removed from staList
        if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
            sendDisAssocNotification(sta->address);
        mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::NOT_AUTHENTICATED;
        sta->authSeqExpected = 1;
    }
}

void Ieee80211MgmtAp::handleAssociationRequestFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "AP:AssociationRequestFrame:len:" << packet->getByteLength() << endl;

    EV << "Processing AssociationRequest frame\n";
    // "11.3.2 AP association procedures"
    StaInfo *sta = lookupSenderSTA(header);
    if (!sta || mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::NOT_AUTHENTICATED) {
        // STA not authenticated: send error and return
        const auto& body = makeShared<Ieee80211DeauthenticationFrame>();
        body->setReasonCode(RC_NONAUTH_ASS_REQUEST);
        sendManagementFrame("Deauth", body, ST_DEAUTHENTICATION, header->getTransmitterAddress());
        delete packet;
        return;
    }

    EV << "AP:enableFils:" << enableFils << ", sta->enableFils:" << sta->enableFils << endl;
    if (enableFils & sta->enableFils) {
        handleFilsAssocReqFrame(packet, header);
        return;
    }

    //Config histogram
    emit(assocTimesSignal,simTime()-sta->authTime+0.0000821);
    delete packet;

    // mark STA as associated
    if (mib->bssAccessPointData.stations[sta->address] != Ieee80211Mib::ASSOCIATED)
        sendAssocNotification(sta->address);
    mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::ASSOCIATED;    // XXX this should only take place when MAC receives the ACK for the response

    // send OK response
    const auto& body = makeShared<Ieee80211AssociationResponseFrame>();
    body->setStatusCode(SC_SUCCESSFUL);
    body->setAid(0);    //XXX
    body->setSupportedRates(supportedRates);
    body->setEnableFils(enableFils & sta->enableFils);
    body->setChunkLength(B(2 + 2 + 2 + body->getSupportedRates().numRates + 2));

    sendManagementFrame("AssocResp-OK", body, ST_ASSOCIATIONRESPONSE, sta->address);
}

void Ieee80211MgmtAp::handleFilsAssocReqFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Processing FILS AssociationRequest frame:pk:" << packet << "\n";


    // "11.3.2 AP association procedures"
    StaInfo *sta = lookupSenderSTA(header);
    if (!sta || mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::NOT_AUTHENTICATED) {
        // STA not authenticated: send error and return
        const auto& body = makeShared<Ieee80211DeauthenticationFrame>();
        body->setReasonCode(RC_NONAUTH_ASS_REQUEST);
        sendManagementFrame("Deauth", body, ST_DEAUTHENTICATION, header->getTransmitterAddress());
        delete packet;
        return;
    }
    // send FILS ASSOC request
    EV << "Sending FILS_ASSOC request frame from Mgmt to Mac" << "\n";
    //Ieee80211AssociationRequestFrame has no "chunkLength" -> getTotalLength() == B(-1)
    const auto& body = makeShared<Ieee80211AuthenticationFrame>();//dummy body
    sendManagementFrame("Assoc-REQ", body, ST_FILS_ASSOC_REQ, header->getTransmitterAddress());

    delete packet;
}

void Ieee80211MgmtAp::handleFilsAssocRespFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Ieee80211MgmtAp::handleFilsAssocRespFrame\n";
    // STA entry is exist
    EV << "DestAddr:" << packet->getTag<MacAddressReq>()->getDestAddress() << "\n";
    StaInfo *sta = &staList[packet->getTag<MacAddressReq>()->getDestAddress()];
    if (!sta) {
        throw cRuntimeError("Ieee80211MgmtAp::handleFilsAssocRespFrame  not find STA");
    }
    // mark STA as associated
    if (mib->bssAccessPointData.stations[sta->address] != Ieee80211Mib::ASSOCIATED)
        sendAssocNotification(sta->address);
    mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::ASSOCIATED;    // XXX this should only take place when MAC receives the ACK for the response

    // send OK response
    const auto& body = makeShared<Ieee80211AssociationResponseFrame>();
    body->setStatusCode(SC_SUCCESSFUL);
    body->setAid(0);    //XXX
    body->setSupportedRates(supportedRates);
    EV << "AP:enableFils:" << enableFils << ", sta->enableFils:" << sta->enableFils << endl;
    body->setEnableFils(enableFils & sta->enableFils);
    body->setAuthTime(sta->authTime);
    body->setChunkLength(B(2 + 2 + 2 + body->getSupportedRates().numRates + 2 + 110));

    //Config histogram
    emit(assocTimesSignal,simTime()-sta->authTime+0.0000821);

    sendManagementFrame("AssocResp-OK", body, ST_ASSOCIATIONRESPONSE, sta->address);
}

void Ieee80211MgmtAp::setRoutingTable(MacAddress staAddr, MacAddress apAddr)
{
    EV << "setRoutingTable:add route of STA address to wifiRouter, STA:" << staAddr << ", AP:" << apAddr << endl;
    //add route to wifiRouter
    if (nullptr != irt) {
#if 1
       // create gateway route
        route = new Ipv4Route();
        InterfaceEntry* interfaceEntry = nullptr;
        IInterfaceTable* interfaceTable;
        char interfaceName[20];
        char car[40];
        //STA: search & set STA ipv4 address
        EV << "numUe:" << numUe << endl;
        for (int i = 0; i < numUe; i++ ) { //STA[x] loop
            sprintf(car, "^.^.^.car[%d].interfaceTable", i);
            cModule *mod = this->getModuleByPath(car);
            if (!mod) {
                EV << "car[" << i << "] interfacetable is not found, skipped." << endl;
                continue;
            }
            interfaceTable = dynamic_cast<IInterfaceTable*>(mod);
            sprintf(interfaceName, "wlan0");
            cPatternMatcher interfaceMatcher((const char*)interfaceName, false, true, false);
            for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
                interfaceEntry = interfaceTable->getInterface(i);
                if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                    break;
                }
            }
            if (interfaceEntry) {
                //do nothing
            } else {
                throw cRuntimeError("Can not get Interface id (STA:wlan0)");
            }
            EV << "STA[" << i << "]:" << interfaceEntry->getMacAddress() << endl;
            if (interfaceEntry->getMacAddress() == staAddr) {//match MAC address
                route->setDestination(interfaceEntry->getIpv4Address());//STA address
                break;
            }
        }
        route->setNetmask(Ipv4Address("255.255.255.255"));//STA(host) only

        //AP: search & set AP_eth0 ipv4 address
        interfaceEntry = nullptr;
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        sprintf(interfaceName, "eth0");
        cPatternMatcher interfaceMatcher((const char*)interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            interfaceEntry = interfaceTable->getInterface(i);
            if (interfaceMatcher.matches(interfaceEntry->getInterfaceName())){
                break;
             }
        }
        if (interfaceEntry) {
            //do nothing
        } else {
            throw cRuntimeError("AP:Can not get Interface id (wlan0)");
        }
        EV << "AP(ipv4):" << interfaceEntry->getIpv4Address() << endl;
        route->setGateway(interfaceEntry->getIpv4Address());//AP's eth0 ipv4 address

        //wifiRouter: eth[x+1] <-> AP[x], eth[0]<->server
        interfaceEntry = nullptr;
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("wifiRouterIfTableModule"), this);
        //get AP index
        cModule *mod = this->getModuleByPath("^.^.");//AP
        if (!mod) {
            throw cRuntimeError("AP:Can not get AP's pointer(cModule*)");
        }
        sprintf(interfaceName, "eth%d", mod->getIndex()+1);//AP[x] -> eth'x+1'
        EV << "AP[" << mod->getIndex() << "], router:eth[" << mod->getIndex() + 1 << "]" << endl;
        cPatternMatcher interfaceMatcherRouter((const char*)interfaceName, false, true, false);
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            interfaceEntry = interfaceTable->getInterface(i);
            if (interfaceMatcherRouter.matches(interfaceEntry->getInterfaceName())){
                break;
             }
        }
        if (interfaceEntry) {
             //do nothing
        } else {
            throw cRuntimeError("Can not get Interface id (wlan0)");
        }
        //delete old route
        Ipv4Route *routeExist;
        for (int i=0; i < irt->getNumRoutes(); i++) {
            routeExist = irt->getRoute(i);
            if (routeExist->getDestination() == route->getDestination()) {
                irt->deleteRoute(routeExist);
            }
        }
        //add route
        route->setInterface(interfaceEntry);
        route->setSourceType(Ipv4Route::MANUAL);
        irt->addRoute(route);
        EV << "set route:" << route << endl;
#endif
    }
    else
    {
        cMessage("Not find wifiRouter routing table");
    }
}

void Ieee80211MgmtAp::handleAssociationResponseFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    dropManagementFrame(packet);
}

void Ieee80211MgmtAp::handleReassociationRequestFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Processing ReassociationRequest frame\n";

    // "11.3.4 AP reassociation procedures" -- almost the same as AssociationRequest processing
    StaInfo *sta = lookupSenderSTA(header);
    if (!sta || mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::NOT_AUTHENTICATED) {
        // STA not authenticated: send error and return
        const auto& body = makeShared<Ieee80211DeauthenticationFrame>();
        body->setReasonCode(RC_NONAUTH_ASS_REQUEST);
        sendManagementFrame("Deauth", body, ST_DEAUTHENTICATION, header->getTransmitterAddress());
        delete packet;
        return;
    }

    delete packet;

    // mark STA as associated
    mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::ASSOCIATED;    // XXX this should only take place when MAC receives the ACK for the response

    // send OK response
    const auto& body = makeShared<Ieee80211ReassociationResponseFrame>();
    body->setStatusCode(SC_SUCCESSFUL);
    body->setAid(0);    //XXX
    body->setSupportedRates(supportedRates);
    body->setChunkLength(B(2 + (2 + ssid.length()) + (2 + supportedRates.numRates) + 6));
    body->setChunkLength(B(2 + (2 + ssid.length()) + (2 + supportedRates.numRates) + 6));
    sendManagementFrame("ReassocResp-OK", body, ST_REASSOCIATIONRESPONSE, sta->address);
}

void Ieee80211MgmtAp::handleReassociationResponseFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    dropManagementFrame(packet);
}

void Ieee80211MgmtAp::handleDisassociationFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    StaInfo *sta = lookupSenderSTA(header);
    delete packet;

    if (sta) {
        if (mib->bssAccessPointData.stations[sta->address] == Ieee80211Mib::ASSOCIATED)
            sendDisAssocNotification(sta->address);
        mib->bssAccessPointData.stations[sta->address] = Ieee80211Mib::AUTHENTICATED;
    }
}

void Ieee80211MgmtAp::handleBeaconFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    dropManagementFrame(packet);
}

void Ieee80211MgmtAp::handleProbeRequestFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    EV << "Processing ProbeRequest frame\n";

    const auto& requestBody = packet->peekData<Ieee80211ProbeRequestFrame>();
    bool flgBroadCast = false;

    if (strcmp(requestBody->getSSID(), "") != 0 && strcmp(requestBody->getSSID(), ssid.c_str()) != 0) {
        EV << "SSID `" << requestBody->getSSID() << "' does not match, ignoring frame\n";
        dropManagementFrame(packet);
        return;
    }

    MacAddress staAddress;
    if(flgBroadCast) {
        // BROADCAST
        EV << "Sending Broadcast ProbeResponse frame\n";
        staAddress = MacAddress::BROADCAST_ADDRESS;
    } else {
        // UNICAST
        EV << "Sending Unicast ProbeResponse frame\n";
        staAddress = header->getTransmitterAddress();
    }

    delete packet;

    //EV << "Sending ProbeResponse frame\n";
    const auto& body = makeShared<Ieee80211ProbeResponseFrame>();
    body->setSSID(ssid.c_str());
    body->setSupportedRates(supportedRates);
    body->setBeaconInterval(beaconInterval);
    body->setChannelNumber(channelNumber);
    body->setChunkLength(B(8 + 2 + 2 + (2 + ssid.length()) + (2 + supportedRates.numRates)));
    sendManagementFrame("ProbeResp", body, ST_PROBERESPONSE, staAddress);
}

void Ieee80211MgmtAp::handleProbeResponseFrame(Packet *packet, const Ptr<const Ieee80211MgmtHeader>& header)
{
    dropManagementFrame(packet);
}

void Ieee80211MgmtAp::sendAssocNotification(const MacAddress& addr)
{
    NotificationInfoSta notif;
    notif.setApAddress(mib->address);
    notif.setStaAddress(addr);
    emit(l2ApAssociatedSignal, &notif);
}

void Ieee80211MgmtAp::sendDisAssocNotification(const MacAddress& addr)
{
    NotificationInfoSta notif;
    notif.setApAddress(mib->address);
    notif.setStaAddress(addr);
    emit(l2ApDisassociatedSignal, &notif);
}

void Ieee80211MgmtAp::start()
{
    Ieee80211MgmtApBase::start();
    scheduleAt(simTime() + uniform(0, beaconInterval), beaconTimer);
    nextBeaconTime = simTime() + uniform(0, filsDiscoveryInterval);
    scheduleAt(nextBeaconTime, filsDiscoveryTimer);
}

void Ieee80211MgmtAp::stop()
{
    cancelEvent(beaconTimer);
    staList.clear();
    Ieee80211MgmtApBase::stop();
}

void Ieee80211MgmtAp::processFrame(Packet *packet, const Ptr<const Ieee80211DataOrMgmtHeader>& header)
{
    EV << "Ieee80211MgmtAp::processFrame\n";

    switch (header->getType()) {
        case ST_FILS_AUTH_RESP:
            numMgmtFramesReceived++;
            handleFilsAuthRespFrame(packet, dynamicPtrCast<const Ieee80211MgmtHeader>(header));
            break;

        case ST_FILS_ASSOC_RESP:
            numMgmtFramesReceived++;
            handleFilsAssocRespFrame(packet, dynamicPtrCast<const Ieee80211MgmtHeader>(header));
            break;
        case ST_ACTION:
            EV << "AP receiaved FD Frame\n";
            break;

        default:
            Ieee80211MgmtBase::processFrame(packet, header);
            break;
    }
}

} // namespace ieee80211

} // namespace inet

