//
// Copyright (C) 2011 Andras Varga
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// This program is based on "src/inet/applications/udpapp/UdpEchoApp.h".
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

#ifndef __INET_UDPECHOAPPDELAY_H
#define __INET_UDPECHOAPPDELAY_H

#include "inet/common/INETDefs.h"

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

namespace inet {

class INET_API UdpEchoAppDelay : public UdpEchoApp
{
  protected:
    int counter = 0;
    enum EchoType {
        RE_SEND_TIMEOUT = 123
    };
    int reSendFlag = 0;
    L3Address remoteAddressTo;
    int srcPortTo;
    cMessage *reSendTo = nullptr;
    Packet *pkt_to = nullptr;
    int msgLength;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void socketDataArrived(UdpSocket *socket, Packet *pk) override;
    virtual void sendEcho(Packet *pkt);
    virtual bool reSendTimeout(void);
    virtual void makeSendPacket(L3Address destAddr, int destPort, int len, int numSent);
  public:
    UdpEchoAppDelay() {}
    virtual ~UdpEchoAppDelay();
};

} // namespace inet

#endif // ifndef __INET_UDPECHOAPPDELAY_H

