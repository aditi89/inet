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

#include "inet/common/checksum/EthernetCRC.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/protocol/ethernet/FragmentFcsVerification.h"
#include "inet/protocol/ethernet/FragmentTag_m.h"
#include "inet/protocol/IProtocol.h"

namespace inet {

Define_Module(FragmentFcsVerification);

void FragmentFcsVerification::initialize(int stage)
{
    PacketFilterBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        registerService(IProtocol::fcs, nullptr, inputGate);
        registerProtocol(IProtocol::fcs, nullptr, outputGate);
    }
}

bool FragmentFcsVerification::matchesPacket(Packet *packet)
{
    const auto& header = packet->popAtBack<EthernetFragmentFcs>(B(4));
    auto fragmentTag = packet->getTag<FragmentTag>();
    fragmentTag->setLastFragment(!header->getInverted());
    if (fragmentTag->getFirstFragment())
        completeFcs = 0;
    switch (header->getFcsMode()) {
        case FCS_DISABLED:
            // if the FCS mode is disabled, then the check passes if the FCS is 0
            return header->getFcs() == 0x00000000L;
        case FCS_DECLARED_CORRECT: {
            // if the FCS mode is declared to be correct, then the check passes if and only if the chunks are correct
            const auto& data = packet->peekData();
            return header->isCorrect() && data->isCorrect();
        }
        case FCS_DECLARED_INCORRECT:
            // if the FCS mode is declared to be incorrect, then the check fails
            return false;
        case FCS_COMPUTED: {
            if (header->getFcs() == 0x00000000L)
                // if the FCS mode is computed and the FCS is 0 (disabled), then the check passes
                return true;
            else {
                // otherwise compute the FCS, the check passes if the result is 0xFFFF (includes the received FCS) and the chunks are correct
                const auto& data = packet->peekDataAsBytes();
                auto bufferLength = B(data->getChunkLength()).get();
                auto buffer = new uint8_t[bufferLength];
                data->copyToBuffer(buffer, bufferLength);
                completeFcs = ethernetCRC(buffer, bufferLength, completeFcs);
                uint32_t computedFcs = ethernetCRC(buffer, bufferLength);
                delete [] buffer;
                auto receivedFcs = header->getFcs();
                bool lastFragment = receivedFcs != (computedFcs ^ 0xFFFF0000);
                fragmentTag->setLastFragment(lastFragment);
                return !lastFragment || receivedFcs == completeFcs;
            }
        }
        default:
            throw cRuntimeError("Unknown FCS mode");
    }
}

} // namespace inet

