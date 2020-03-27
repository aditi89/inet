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

#include "inet/protocol/ethernet/EthernetDefragmentation.h"
#include "inet/protocol/ethernet/FragmentTag_m.h"

namespace inet {

Define_Module(EthernetDefragmentation);

void EthernetDefragmentation::initialize(int stage)
{
    PacketPusherBase::initialize(stage);
}

void EthernetDefragmentation::pushPacket(Packet *fragmentPacket, cGate *gate)
{
    Enter_Method("pushPacket");
    auto fragmentTag = fragmentPacket->getTag<FragmentTag>();
    if (fragmentTag->getFirstFragment()) {
        std::string name = fragmentPacket->getName();
        name = name.substr(0, name.rfind('-'));
        packet = new Packet(name.c_str());
    }
    packet->insertAtBack(fragmentPacket->peekData());
    processedTotalLength += fragmentPacket->getDataLength();
    numProcessedPackets++;
    updateDisplayString();
    if (fragmentTag->getLastFragment()) {
        pushOrSendPacket(packet, outputGate, consumer);
        packet = nullptr;
    }
    delete fragmentPacket;
}

} // namespace inet

