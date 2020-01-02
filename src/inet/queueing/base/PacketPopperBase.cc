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
#include "inet/common/Simsignals.h"
#include "inet/queueing/base/PacketPopperBase.h"

namespace inet {
namespace queueing {

void PacketPopperBase::initialize(int stage)
{
    PacketProcessorBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        inputGate = gate("in");
        outputGate = gate("out");
        collector = findConnectedModule<IActivePacketSink>(outputGate);
        provider = findConnectedModule<IPassivePacketSource>(inputGate);
    }
    else if (stage == INITSTAGE_QUEUEING) {
        if (collector != nullptr)
            checkPopPacketSupport(inputGate);
        if (provider != nullptr)
            checkPopPacketSupport(outputGate);
    }
}

bool PacketPopperBase::canPopSomePacket(cGate *gate) const
{
    return provider->canPopSomePacket(inputGate->getPathStartGate());
}

Packet *PacketPopperBase::canPopPacket(cGate *gate) const
{
    return provider->canPopPacket(inputGate->getPathStartGate());
}

void PacketPopperBase::handleCanPopPacket(cGate *gate)
{
    Enter_Method("handleCanPopPacket");
    if (collector != nullptr)
        collector->handleCanPopPacket(outputGate);
}

} // namespace queueing
} // namespace inet

