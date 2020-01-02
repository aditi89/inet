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

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/protocol/contract/IProtocol.h"
#include "inet/protocol/fragmentation/DefragmenterBase.h"
#include "inet/protocol/fragmentation/FragmentNumberHeader_m.h"
#include "inet/protocol/fragmentation/FragmentTag_m.h"

namespace inet {

Define_Module(DefragmenterBase);

void DefragmenterBase::initialize(int stage)
{
    PacketPusherBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        headerPosition = parseHeaderPosition(par("headerPosition"));
        if (headerPosition != HP_NONE) {
            registerService(IProtocol::fragmentation, inputGate, inputGate);
            registerProtocol(IProtocol::fragmentation, outputGate, outputGate);
        }
    }
}

void DefragmenterBase::pushPacket(Packet *fragmentPacket, cGate *gate)
{
    Enter_Method("pushPacket");
    bool firstFragment;
    bool lastFragment;
    int fragmentNumber;
    int fragmentCount;
    if (headerPosition != HP_NONE) {
        Ptr<const FragmentNumberHeader> fragmentHeader;
        switch (headerPosition) {
            case HP_FRONT:
                fragmentHeader = fragmentPacket->popAtFront<FragmentNumberHeader>();
                break;
            case HP_BACK:
                fragmentHeader = fragmentPacket->popAtBack<FragmentNumberHeader>(B(1));
                break;
            default:
                throw cRuntimeError("Unknown headerPosition parameter value");
        }
        firstFragment = fragmentHeader->getFragmentNumber() == 0;
        lastFragment = fragmentHeader->getLastFragment();
        fragmentNumber = fragmentHeader->getFragmentNumber();
        fragmentCount = -1;
    }
    else {
        auto fragmentTag = fragmentPacket->getTag<FragmentTag>();
        firstFragment = fragmentTag->getFirstFragment();
        lastFragment = fragmentTag->getLastFragment();
        fragmentNumber = fragmentTag->getFragmentNumber();
        fragmentCount = fragmentTag->getNumFragments();
    }
    if (expectedFragmentNumber != fragmentNumber)
        throw cRuntimeError("Unexpected fragment");
    else {
        if (firstFragment) {
            std::string name = fragmentPacket->getName();
            name = name.substr(0, name.rfind('-'));
            packet = new Packet(name.c_str());
        }
        expectedFragmentNumber++;
        packet->insertAtBack(fragmentPacket->peekData());
        processedTotalLength += fragmentPacket->getDataLength();
        numProcessedPackets++;
        updateDisplayString();
        if (lastFragment) {
            pushOrSendPacket(packet, outputGate, consumer);
            packet = nullptr;
            expectedFragmentNumber = 0;
            if (par("deleteSelf"))
                deleteModule();
        }
        delete fragmentPacket;
    }
}

} // namespace inet

