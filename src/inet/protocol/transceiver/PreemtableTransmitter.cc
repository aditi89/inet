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

#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/protocol/transceiver/PreemtableTransmitter.h"

namespace inet {

Define_Module(PreemtableTransmitter);

// TODO: rename to PreemptableTransmitter
void PreemtableTransmitter::initialize(int stage)
{
    PassivePacketSinkBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        inputGate = gate("in");
        outputGate = gate("out");
        datarate = bps(par("datarate"));
        producer = findConnectedModule<IActivePacketSource>(inputGate);
        txEndTimer = new cMessage("TxEndTimer");
    }
}

PreemtableTransmitter::~PreemtableTransmitter()
{
    cancelAndDelete(txEndTimer);
}

void PreemtableTransmitter::handleMessage(cMessage *message)
{
    if (message == txEndTimer)
        endTx();
    else
        throw cRuntimeError("Unknown message");
}

void PreemtableTransmitter::pushPacket(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);
    if (txPacket != nullptr)
        abortTx();
    startTx(packet);
}

void PreemtableTransmitter::pushPacketStart(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacketStart");
    take(packet);
    startTx(packet);
}

void PreemtableTransmitter::pushPacketProgress(Packet *packet, b position, b extraProcessableLength, cGate *gate)
{
    Enter_Method("pushPacketProgress");
    simtime_t timePosition = simTime() - txStartTime;
    int bitPosition = std::floor(datarate.get() * timePosition.dbl());
    delete txPacket;
    txPacket = packet;
    auto oldPacketProtocolTag = txPacket->removeTag<PacketProtocolTag>();
    txPacket->clearTags();
    auto newPacketProtocolTag = txPacket->addTag<PacketProtocolTag>();
    *newPacketProtocolTag = *oldPacketProtocolTag;
    delete oldPacketProtocolTag;
    auto duration = calculateDuration(txPacket);
    auto signal = new Signal(txPacket->getName());
    signal->encapsulate(txPacket->dup());
    signal->setDuration(duration);
    sendPacketProgress(signal, outputGate, duration, bitPosition, timePosition);
    scheduleTxEndTimer(signal, timePosition);
}

void PreemtableTransmitter::pushPacketEnd(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacketEnd");
    throw cRuntimeError("TODO");
}

void PreemtableTransmitter::startTx(Packet *packet)
{
    ASSERT(txPacket == nullptr);
    txPacket = packet;
    auto oldPacketProtocolTag = txPacket->removeTag<PacketProtocolTag>();
    txPacket->clearTags();
    auto newPacketProtocolTag = txPacket->addTag<PacketProtocolTag>();
    *newPacketProtocolTag = *oldPacketProtocolTag;
    delete oldPacketProtocolTag;
    txStartTime = simTime();
    auto duration = calculateDuration(txPacket);
    auto signal = new Signal(txPacket->getName());
    signal->encapsulate(txPacket->dup());
    signal->setDuration(duration);
    EV_INFO << "Starting transmission: packetName = " << txPacket->getName() << ", length = " << txPacket->getTotalLength() << ", duration = " << duration << std::endl;
    scheduleTxEndTimer(signal, 0);
    sendPacketStart(signal, outputGate, duration);
}

void PreemtableTransmitter::endTx()
{
    EV_INFO << "Ending transmission: packetName = " << txPacket->getName() << std::endl;
    auto duration = calculateDuration(txPacket);
    auto signal = new Signal(txPacket->getName());
    signal->encapsulate(txPacket->dup());
    signal->setDuration(duration);
    sendPacketEnd(signal, outputGate, duration);
    producer->handlePushPacketConfirmation(txPacket, inputGate->getPathStartGate(), true);
    delete txPacket;
    txPacket = nullptr;
    txStartTime = -1;
    producer->handleCanPushPacket(inputGate->getPathStartGate());
}

void PreemtableTransmitter::abortTx()
{
    cancelEvent(txEndTimer);
    b transmittedLength = getPushedPacketConfirmedLength(txPacket, inputGate);
    txPacket->eraseAtBack(txPacket->getTotalLength() - transmittedLength);
    auto duration = calculateDuration(txPacket);
    EV_INFO << "Aborting transmission: packetName = " << txPacket->getName() << ", length = " << txPacket->getTotalLength() << ", duration = " << duration << std::endl;
    auto signal = new Signal(txPacket->getName());
    signal->encapsulate(txPacket->dup());
    signal->setDuration(duration);
    sendPacketEnd(signal, outputGate, duration);
    producer->handlePushPacketConfirmation(txPacket, inputGate->getPathStartGate(), true);
    txPacket = nullptr;
    txStartTime = -1;
    producer->handleCanPushPacket(inputGate->getPathStartGate());
}

simtime_t PreemtableTransmitter::calculateDuration(Packet *packet)
{
    return packet->getTotalLength().get() / datarate.get();
}

void PreemtableTransmitter::scheduleTxEndTimer(Signal *signal, simtime_t timePosition)
{
    if (txEndTimer->isScheduled())
        cancelEvent(txEndTimer);
    scheduleAt(simTime() + signal->getDuration() - timePosition, txEndTimer);
}

b PreemtableTransmitter::getPushedPacketConfirmedLength(Packet *packet, cGate *gate)
{
    simtime_t transmissionDuration = simTime() - txStartTime;
    return b(std::floor(datarate.get() * transmissionDuration.dbl()));
}

} // namespace inet
