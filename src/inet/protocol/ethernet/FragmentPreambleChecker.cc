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
    if (header->getPreambleType() != SMD_Sx && header->getPreambleType() != SMD_Cx)
        return false;
    else {
        auto fragmentTag = packet->addTag<FragmentTag>();
        if (header->getSmdNumber() == smdNumber) {
            if (header->getFragmentNumber() == fragmentNumber) {
                if (header->getPreambleType() == SMD_Cx)
                    fragmentNumber = (fragmentNumber + 1) % 4;
                return true;
            }
            else {
                smdNumber = -1;
                return false;
            }
        }
        else {
            if (header->getFragmentNumber() == 0) {
                smdNumber = header->getSmdNumber();
                fragmentNumber = 0;
                fragmentTag->setFirstFragment(true);
                return true;
            }
            else {
                smdNumber = -1;
                return false;
            }
        }
    }
}

} // namespace inet

