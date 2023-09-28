//
// Copyright (C) OpenSim Ltd.
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is based on "src/inet/node/wireless/AccessPoint.ned".
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

//package inet.node.wireless;

//import inet.applications.contract.IApp;
//import inet.common.MessageDispatcher;
//import inet.common.lifecycle.NodeStatus;
//import inet.common.packet.recorder.PcapRecorder;
import inet.linklayer.contract.IEthernetInterface;
import inet.linklayer.contract.IMacAddressTable;
import inet.linklayer.contract.IMacRelayUnit;
import inet.linklayer.contract.IWirelessInterface;
import inet.mobility.contract.IMobility;
import inet.networklayer.common.InterfaceTable;
//import inet.networklayer.ipv4.Ipv4NetworkLayer;
//import inet.networklayer.contract.INetworkLayer;

//FILS
package inet.node.inet;

//
// A generic access point supporting multiple wireless radios, and
// multiple ethernet ports. The type of the ethernet MAC, relay unit
// and wireless card can be specified as parameters.
//
// By default, the access point is stationary (~StationaryMobility),
// but that can also be configured by a parameter.
//
// The wlan[*].mgmt.typename can be configured for different management types
// currently it can be: ~Ieee80211MgmtApSimplified and ~Ieee80211MgmtAp.
// By default it is ~Ieee80211MgmtAp. The Simplified version does not
// support channel scanning, authentication and association .
// In this case, nodes must explicitly specify the hardware address
// of the wlan card they want to be associated with.
//
module AccessPointFils extends StandardHost
{
    parameters:
        @networkNode();
        @labels(node,ethernet-node,wireless-node);
        @display("i=device/accesspoint");
        numWlanInterfaces = default(1);
        wlan[*].mgmt.typename = default("Ieee80211MgmtAp");
        wlan[*].llc.typename = default("Ieee80211Portal");
        wlan[*].agent.typename = default("");
        wlan[*].radio.antenna.mobilityModule = default("^.^.^.mobility");
        wlan[*].mgmt.filsWrappedDataLen = default(8);
        //eth[*].encap.typename = default("EtherEncapDummy");//FILS: comment out when the AP has application layer
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        relayUnit.hasStp = false;
    //gates:
    //    input radioIn[numWlanInterfaces] @directIn;
    //    inout ethg[] @labels(EtherFrame-conn);
    submodules:
        macTable: <default("MacAddressTable")> like IMacAddressTable {
            parameters:
                @display("p=100,300;is=s");
        }
        relayUnit: <default(firstAvailable("Ieee8021dRelay","MacRelayUnit"))> like IMacRelayUnit if sizeof(ethg)+numWlanInterfaces > 1 && typename != "" {
            parameters:
                @display("p=579,331");
        }

    connections allowunconnected:
        nl.out++ --> relayUnit.ifIn if sizeof(ethg)+numWlanInterfaces > 1 && exists(relayUnit);
        nl.in++ <-- relayUnit.ifOut if sizeof(ethg)+numWlanInterfaces > 1 && exists(relayUnit);
}

