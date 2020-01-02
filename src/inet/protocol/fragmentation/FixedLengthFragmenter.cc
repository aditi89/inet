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

#include "inet/common/ProtocolTag_m.h"
#include "inet/protocol/fragmentation/FixedLengthFragmenter.h"
#include "inet/protocol/fragmentation/FragmentNumberHeader_m.h"
#include "inet/protocol/contract/IProtocol.h"

namespace inet {

Define_Module(FixedLengthFragmenter);

void FixedLengthFragmenter::initialize(int stage)
{
    FragmenterBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        maxFragmentLength = b(par("maxFragmentLength"));
        fragmentHeaderLength = b(par("fragmentHeaderLength"));
    }
}

std::vector<b> FixedLengthFragmenter::computeFragmentLengths(Packet *packet) const
{
    Enter_Method_Silent("computeFragmentLengths");
    if (maxFragmentLength >= packet->getTotalLength())
        // TODO: 1 element?
        return std::vector<b>();
    else {
        std::vector<b> fragmentLengths;
        b remainingLength = packet->getTotalLength();
        for (int i = 0; fragmentHeaderLength + remainingLength > maxFragmentLength; i++) {
            auto fragmentLength = maxFragmentLength - fragmentHeaderLength;
            fragmentLengths.push_back(fragmentLength);
        }
        if (remainingLength != b(0))
            fragmentLengths.push_back(remainingLength);
        return fragmentLengths;
    }
}

} // namespace inet

