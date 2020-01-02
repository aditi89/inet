//
// Copyright (C) OpenSim Ltd.
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

#ifndef __INET_MARKOVSCHEDULER_H
#define __INET_MARKOVSCHEDULER_H

#include "inet/queueing/base/PacketSchedulerBase.h"
#include "inet/queueing/contract/IActivePacketSource.h"

namespace inet {
namespace queueing {

class INET_API MarkovScheduler : public PacketSchedulerBase, public IPassivePacketSink, public IActivePacketSource
{
  protected:
    std::vector<IActivePacketSource *> producers;
    IPassivePacketSink *consumer = nullptr;

    std::vector<std::vector<double>> transitionProbabilities;
    std::vector<cDynamicExpression> waitIntervals;

    int state;

    cMessage *transitionTimer = nullptr;
    cMessage *waitTimer = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;

    virtual int schedulePacket() override;
    virtual void scheduleWaitTimer();

  public:
    virtual ~MarkovScheduler();

    virtual IPassivePacketSink *getConsumer(cGate *gate) override { return consumer; }

    virtual bool supportsPushPacket(cGate *gate) const override { return true; }
    virtual bool supportsPopPacket(cGate *gate) const override { return true; }

    virtual bool canPushSomePacket(cGate *gate) const override;
    virtual bool canPushPacket(Packet *packet, cGate *gate) const override;
    virtual void pushPacket(Packet *packet, cGate *gate) override;
    virtual void pushPacketStart(Packet *packet, cGate *gate = nullptr) override { }
    virtual void pushPacketEnd(Packet *packet, cGate *gate = nullptr) override { }
    virtual void pushPacketProgress(Packet *packet, b position, b extraProcessableLength = b(0), cGate *gate = nullptr) override { }
    virtual void handlePushPacketConfirmation(Packet *packet, cGate *gate, bool successful) override { }
    virtual b getPushedPacketConfirmedLength(Packet *packet, cGate *gate = nullptr) override { return b(0); }

    virtual void handleCanPushPacket(cGate *gate) override;
    virtual const char *resolveDirective(char directive) const override;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_MARKOVSCHEDULERBASE_H

