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

#include "inet/linklayer/ethernet/EtherPhyFrame_m.h"
#include "inet/protocol/ethernet/FragmentPreambleInsertion.h"
#include "inet/protocol/ethernet/FragmentTag_m.h"

namespace inet {

Define_Module(FragmentPreambleInsertion);

void FragmentPreambleInsertion::initialize(int stage)
{
    PacketFlowBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
    }
}

void FragmentPreambleInsertion::processPacket(Packet *packet)
{
    auto fragmentTag = packet->getTag<FragmentTag>();
    bool firstFragment = fragmentTag->getFirstFragment();
    const auto& header = makeShared<EthernetPhyHeader>();
    header->setFragId(firstFragment ? SMD_Sx[fragmentIndex] : SMD_Cx[fragmentIndex]);
    header->setFragCount(fragmentCount);
    packet->insertAtFront(header);
    fragmentCount = (fragmentCount + 1) % 4;
    if (fragmentCount == 0)
        fragmentIndex++;
}

} // namespace inet

