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

#ifndef __INET_STARTSTOPRECEIVER_H
#define __INET_STARTSTOPRECEIVER_H

#include "inet/physicallayer/common/packetlevel/Signal.h"
#include "inet/queueing/base/PacketQueueingElementBase.h"
#include "inet/queueing/contract/IPacketQueueingElement.h"
#include "inet/queueing/contract/IPassivePacketSink.h"

namespace inet {

using namespace inet::units::values;
using namespace inet::queueing;
using namespace inet::physicallayer;

class INET_API StartStopReceiver : public PacketQueueingElementBase
{
  protected:
    cPar *dataratePar = nullptr;
    cGate *inputGate = nullptr;
    cGate *outputGate = nullptr;
    IPassivePacketSink *consumer = nullptr;

    Signal *rxSignal = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;

    virtual void sendToUpperLayer(Packet *packet);

    virtual void receivePacketStart(cPacket *packet) override;
    virtual void receivePacketProgress(cPacket *packet, int bitPosition, simtime_t timePosition, int extraProcessableBitLength, simtime_t extraProcessableDuration) override;
    virtual void receivePacketEnd(cPacket *packet) override;

  public:
    virtual ~StartStopReceiver();

    virtual bool supportsPushPacket(cGate *gate) const override { return gate == outputGate; }
    virtual bool supportsPopPacket(cGate *gate) const override { return false; }
};

} // namespace inet

#endif // ifndef __INET_STARTSTOPRECEIVER_H

