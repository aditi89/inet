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

#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/protocol/transceiver/Transmitter.h"

namespace inet {

Define_Module(Transmitter);

void Transmitter::initialize(int stage)
{
    PassivePacketSinkBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        inputGate = gate("in");
        outputGate = gate("out");
        producer = findConnectedModule<IActivePacketSource>(inputGate);
        datarate = bps(par("datarate"));
        txEndTimer = new cMessage("endTimer");
    }
}

void Transmitter::handleMessage(cMessage *message)
{
    if (message == txEndTimer)
        producer->handlePushPacketConfirmation(txPacket, inputGate->getPathStartGate(), true);
    else
        PassivePacketSinkBase::handleMessage(message);
}

void Transmitter::pushPacket(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacket");
    txPacket = packet;
    take(txPacket);
    auto oldPacketProtocolTag = txPacket->removeTag<PacketProtocolTag>();
    txPacket->clearTags();
    auto newPacketProtocolTag = txPacket->addTag<PacketProtocolTag>();
    *newPacketProtocolTag = *oldPacketProtocolTag;
    delete oldPacketProtocolTag;
    auto signal = new Signal(packet->getName());
    auto duration = calculateDuration(txPacket);
    signal->setDuration(duration);
    signal->encapsulate(txPacket);
    sendDelayed(signal, 0, outputGate, duration);
    scheduleTxEndTimer(signal);
}

simtime_t Transmitter::calculateDuration(Packet *packet)
{
    return packet->getDataLength().get() / datarate.get();
}

void Transmitter::scheduleTxEndTimer(Signal *signal)
{
    if (txEndTimer->isScheduled())
        cancelEvent(txEndTimer);
    scheduleAt(simTime() + signal->getDuration(), txEndTimer);
}

} // namespace inet

