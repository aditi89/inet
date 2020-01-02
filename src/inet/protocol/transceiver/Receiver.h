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

#ifndef __INET_RECEIVER_H
#define __INET_RECEIVER_H

#include "inet/physicallayer/common/packetlevel/Signal.h"
#include "inet/queueing/base/PacketQueueingElementBase.h"
#include "inet/queueing/contract/IPacketQueueingElement.h"
#include "inet/queueing/contract/IPassivePacketSink.h"

namespace inet {

using namespace inet::units::values;
using namespace inet::queueing;
using namespace inet::physicallayer;

class INET_API Receiver : public PacketQueueingElementBase
{
  protected:
    bps datarate = bps(NaN);

    cGate *outputGate = nullptr;
    IPassivePacketSink *consumer = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;

    virtual void receiveSignal(Signal *signal);
    virtual void sendToUpperLayer(Packet *packet);

  public:
    virtual bool supportsPushPacket(cGate *gate) const override { return gate == outputGate; }
    virtual bool supportsPopPacket(cGate *gate) const override { return false; }
};

} // namespace inet

#endif // ifndef __INET_RECEIVER_H

