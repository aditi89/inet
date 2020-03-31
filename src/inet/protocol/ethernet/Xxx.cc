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

#include "inet/common/DirectionTag_m.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/Simsignals.h"
#include "inet/protocol/ethernet/Xxx.h"

namespace inet {

Define_Module(Xxx);

void Xxx::initialize(int stage)
{
    PacketFlowBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        inbound = par("inbound");
    }
}

void Xxx::processPacket(Packet *packet)
{
}

void Xxx::pushPacket(Packet *packet, cGate *gate)
{
    emitPacket(packet);
    PacketFlowBase::pushPacket(packet, gate);
}

//void Xxx::pushPacketStart(Packet *packet, cGate *gate)
//{
//    PacketFlowBase::pushPacketStart(packet, gate);
//}
//
//void Xxx::pushPacketProgress(Packet *packet, b position, b extraProcessableLength, cGate *gate)
//{
//    PacketFlowBase::pushPacketProgress(packet, position, extraProcessableLength, gate);
//    if (packet->getTotalLength() == position + extraProcessableLength)
//}
//
//void Xxx::pushPacketEnd(Packet *packet, cGate *gate)
//{
//    PacketFlowBase::pushPacketEnd(packet, gate);
//}

void Xxx::handlePushPacketConfirmation(Packet *packet, cGate *gate, bool successful)
{
    emitPacket(packet);
    PacketFlowBase::handlePushPacketConfirmation(packet, gate, successful);
}

void Xxx::emitPacket(Packet *packet)
{
    auto p = new Packet(packet->getName(), packet->peekAllAsBytes());
    p->copyTags(*packet);
    p->addTagIfAbsent<DirectionTag>()->setInbound(inbound);
    p->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ethernetPhy);
    emit(packetSentToLowerSignal, p);
    delete p;
}

} // namespace inet

