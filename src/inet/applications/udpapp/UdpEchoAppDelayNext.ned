//
// Copyright (C) 2011 Andras Varga
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is based on "src/inet/applications/udpapp/UdpEchoApp.ned".
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

package inet.applications.udpapp;

import inet.applications.contract.IApp;

//
// Listens on an UDP port, and sends back each received packet to its sender.
// Note: when used together with ~UdpBasicApp, ~UdpBasicApp's "received packet
// lifetime" statistic will record round-trip times.
//
simple UdpEchoAppDelayNext like IApp
{
    parameters:
        string interfaceTableModule;   // The path to the InterfaceTable module
        int localPort;  // local port to listen on
        @display("i=block/app");
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // extra time after lifecycle stop operation finished
        double stopOperationTimeout @unit(s) = default(2s);    // timeout value for lifecycle stop operation
        double delayTime @unit(s) = default(0s); 
        int count = default(0x7fffffff);
        string remoteSvrAddr = default("");
        int remotePortSameAsLocal = default(0);
        double localAddrInterval @unit(s) = default(0.01s); 
        double reSendTimeout @unit(s) = default(0s);
        bool nextPort = default(false);
        string packetName = default("UdpEchoAppDelayNext");
        @signal[packetSent](type=inet::Packet);
        @statistic[echoedPk](title="packets echoed"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}

