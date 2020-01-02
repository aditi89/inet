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

#ifndef __INET_PACKETFLOWBASE_H
#define __INET_PACKETFLOWBASE_H

#include "inet/queueing/base/PacketProcessorBase.h"
#include "inet/queueing/contract/IPacketFlow.h"

namespace inet {
namespace queueing {

class INET_API PacketFlowBase : public PacketProcessorBase, public virtual IPacketFlow
{
  protected:
    cGate *inputGate = nullptr;
    IActivePacketSource *producer = nullptr;
    IPassivePacketSource *provider = nullptr;

    cGate *outputGate = nullptr;
    IPassivePacketSink *consumer = nullptr;
    IActivePacketSink *collector = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;
    virtual void processPacket(Packet *packet) = 0;

  public:
    virtual IPassivePacketSink *getConsumer(cGate *gate) override { return this; }
    virtual IPassivePacketSource *getProvider(cGate *gate) override { return this; }

    virtual bool supportsPushPacket(cGate *gate) const override { return true; }
    virtual bool canPushSomePacket(cGate *gate) const override;
    virtual bool canPushPacket(Packet *packet, cGate *gate) const override;
    virtual void pushPacket(Packet *packet, cGate *gate) override;
    virtual void pushPacketStart(Packet *packet, cGate *gate = nullptr) override;
    virtual void pushPacketProgress(Packet *packet, b position, b extraProcessableLength = b(0), cGate *gate = nullptr) override;
    virtual void pushPacketEnd(Packet *packet, cGate *gate = nullptr) override;
    virtual void handlePushPacketConfirmation(Packet *packet, cGate *gate, bool successful) override;
    virtual b getPushedPacketConfirmedLength(Packet *packet, cGate *gate) override;

    virtual bool supportsPopPacket(cGate *gate) const override { return true; }
    virtual bool canPopSomePacket(cGate *gate) const override;
    virtual Packet *canPopPacket(cGate *gate) const override;
    virtual Packet *popPacket(cGate *gate) override;
    virtual Packet *pullPacketStart(cGate *gate = nullptr) override { return nullptr; }
    virtual Packet *pullPacketEnd(cGate *gate = nullptr) override { return nullptr; }
    virtual Packet *pullPacketProgress(b& position, b& extraProcessableLength, cGate *gate = nullptr) override { return nullptr; }
    virtual b getPulledPacketConfirmedLength(Packet *packet, cGate *gate = nullptr) override { return b(0); }
    virtual void handlePullPacketConfirmation(Packet *packet, cGate *gate, bool successful) override { }

    virtual void handleCanPushPacket(cGate *gate) override;
    virtual void handleCanPopPacket(cGate *gate) override;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_PACKETFLOWBASE_H

