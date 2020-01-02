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

#ifndef __INET_PREEMTABLETRANSMITTER_H
#define __INET_PREEMTABLETRANSMITTER_H

#include "inet/physicallayer/common/packetlevel/Signal.h"
#include "inet/queueing/base/PassivePacketSinkBase.h"
#include "inet/queueing/contract/IActivePacketSource.h"

namespace inet {

using namespace inet::units::values;
using namespace inet::queueing;
using namespace inet::physicallayer;

class INET_API PreemtableTransmitter : public PassivePacketSinkBase
{
  protected:
    cGate *inputGate = nullptr;
    cGate *outputGate = nullptr;
    IActivePacketSource *producer = nullptr;

    bps datarate = bps(NaN);

    simtime_t txStartTime = -1;
    cMessage *txEndTimer = nullptr;
    Packet *txPacket = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;

    virtual void startTx(Packet *packet);
    virtual void endTx();
    virtual void abortTx();

    virtual simtime_t calculateDuration(Packet *packet);
    virtual void scheduleTxEndTimer(Signal *signal, simtime_t timePosition);

  public:
    virtual ~PreemtableTransmitter();

    virtual bool supportsPushPacket(cGate *gate) const override { return gate == inputGate; }
    virtual bool supportsPopPacket(cGate *gate) const override { return false; }

    virtual bool canPushSomePacket(cGate *gate = nullptr) const override { return txPacket == nullptr; };
    virtual bool canPushPacket(Packet *packet, cGate *gate = nullptr) const override { return txPacket == nullptr; };
    virtual void pushPacket(Packet *packet, cGate *gate = nullptr) override;
    virtual void pushPacketStart(Packet *packet, cGate *gate = nullptr) override;
    virtual void pushPacketProgress(Packet *packet, b position, b extraProcessableLength = b(0), cGate *gate = nullptr) override;
    virtual void pushPacketEnd(Packet *packet, cGate *gate = nullptr) override;

    virtual b getPushedPacketConfirmedLength(Packet *packet, cGate *gate) override;
};

} // namespace inet

#endif // ifndef __INET_PREEMTABLETRANSMITTER_H

