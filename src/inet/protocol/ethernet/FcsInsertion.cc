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
#include "inet/common/ProtocolTag_m.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/protocol/ethernet/FcsInsertion.h"
#include "inet/protocol/IProtocol.h"

namespace inet {

Define_Module(EthernetFcsInsertion);

void EthernetFcsInsertion::initialize(int stage)
{
    PacketFlowBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        fcsMode = parseFcsMode(par("fcsMode"));
//        registerService(IProtocol::fcs, inputGate, nullptr);
//        registerProtocol(IProtocol::fcs, outputGate, nullptr);
    }
}

void EthernetFcsInsertion::processPacket(Packet *packet)
{
    const auto& header = makeShared<EthernetFcs>();
    header->setFcsMode(fcsMode);
    switch (fcsMode) {
        case FCS_DISABLED:
            // if the FCS mode is disabled, then the FCS is 0
            header->setFcs(0x00000000L);
            break;
        case FCS_DECLARED_CORRECT:
            // if the FCS mode is declared to be correct, then set the FCS to an easily recognizable value
            header->setFcs(0xC00DC00DL);
            break;
        case FCS_DECLARED_INCORRECT:
            // if the FCS mode is declared to be incorrect, then set the FCS to an easily recognizable value
            header->setFcs(0xBAADBAADL);
            break;
        case FCS_COMPUTED: {
            // if the FCS mode is computed, then compute the FCS and set it
            auto data = packet->peekDataAsBytes();
            auto bufferLength = B(data->getChunkLength()).get();
            auto buffer = new uint8_t[bufferLength];
            data->copyToBuffer(buffer, bufferLength);
            uint32_t fcs = ethernetCRC(buffer, bufferLength);
            header->setFcs(fcs);
            delete [] buffer;
            break;
        }
        default:
            throw cRuntimeError("Unknown FCS mode: %d", (int)fcsMode);
    }
    packet->insertAtBack(header);
//    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&IProtocol::fcs);
}

} // namespace inet

