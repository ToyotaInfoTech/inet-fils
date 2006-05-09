//
// Copyright (C) 2006 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

#ifndef IEEE80211_MGMT_BASE_H
#define IEEE80211_MGMT_BASE_H

#include <omnetpp.h>
#include "MACAddress.h"
#include "NotificationBoard.h"
#include "Ieee80211Frame_m.h"
#include "Ieee80211MgmtFrames_m.h"


/**
 * Base class for 802.11 infrastructure mode management component.
 *
 * @author Andras Varga
 */
class INET_API Ieee80211MgmtBase : public cSimpleModule, public INotifiable
{
  protected:
    /** Dispatch to frame processing methods according to frame type */
    virtual void processFrame(Ieee80211BasicFrame *frame);

    /** @name Processing of different frame types */
    //@{
    virtual void handleDataFrame(Ieee80211DataFrame *frame) = 0;
    virtual void handleAuthenticationFrame(Ieee80211AuthenticationFrame *frame) = 0;
    virtual void handleDeauthenticationFrame(Ieee80211DeauthenticationFrame *frame) = 0;
    virtual void handleAssociationRequestFrame(Ieee80211AssociationRequestFrame *frame) = 0;
    virtual void handleAssociationResponseFrame(Ieee80211AssociationResponseFrame *frame) = 0;
    virtual void handleReassociationRequestFrame(Ieee80211ReassociationRequestFrame *frame) = 0;
    virtual void handleReassociationResponseFrame(Ieee80211ReassociationResponseFrame *frame) = 0;
    virtual void handleDisassociationFrame(Ieee80211DisassociationFrame *frame) = 0;
    virtual void handleBeaconFrame(Ieee80211BeaconFrame *frame) = 0;
    virtual void handleProbeRequestFrame(Ieee80211ProbeRequestFrame *frame) = 0;
    virtual void handleProbeResponseFrame(Ieee80211ProbeResponseFrame *frame) = 0;
    //@}
};



#endif
