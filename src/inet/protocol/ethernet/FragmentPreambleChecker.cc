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
#include "inet/protocol/ethernet/FragmentPreambleChecker.h"
#include "inet/protocol/ethernet/FragmentTag_m.h"

namespace inet {

Define_Module(FragmentPreambleChecker);

void FragmentPreambleChecker::initialize(int stage)
{
    PacketFilterBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
    }
}

bool FragmentPreambleChecker::matchesPacket(Packet *packet)
{
    const auto& header = packet->popAtFront<EthernetPhyHeader>();
    auto fragmentTag = packet->getTag<FragmentTag>();
    if (fragmentTag->getFirstFragment()) {
        for (fragmentIndex = 0; fragmentIndex < 4; fragmentIndex++)
            if (SMD_Sx[fragmentIndex] == header->getFragId())
                break;
        if (fragmentIndex == 4)
            return false;
    }
    else if (SMD_Cx[fragmentIndex] != header->getFragId())
        return false;
    if (fragmentCount != header->getFragCount()) {
        fragmentCount = 0;
        return false;
    }
    else
        fragmentCount = (fragmentCount + 1) % 4;
    return true;
}

} // namespace inet

