//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/common/UserPriorityTag_m.h"
#include "inet/protocol/ethernet/FragmentTag_m.h"
#include "inet/protocol/fragmentation/FragmentNumberHeader_m.h"
#include "inet/protocol/IProtocol.h"
#include "inet/protocol/ordering/SequenceNumberHeader_m.h"
#include "inet/protocol/PreemtingServer.h"
#include "inet/queueing/contract/IPacketQueue.h"

namespace inet {

Define_Module(PreemtingServer);

void PreemtingServer::initialize(int stage)
{
    PacketServerBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        roundingLength = b(par("roundingLength"));
        preemtedOutputGate = gate("preemtedOut");
        preemtedConsumer = getConnectedModule<IPassivePacketSink>(preemtedOutputGate);
    }
    else if (stage == INITSTAGE_QUEUEING) {
        checkPushPacketSupport(preemtedOutputGate);
    }
}

void PreemtingServer::startSendingPacket()
{
    packet = provider->popPacket(inputGate->getPathStartGate());
    firstFragment = true;
    take(packet);
    packet->setArrival(getId(), inputGate->getId(), simTime());
    EV_INFO << "Sending packet " << packet->getName() << " started." << endl;
    consumer->pushPacketStart(packet->dup(), outputGate->getPathEndGate());
    processedTotalLength += packet->getDataLength();
    numProcessedPackets++;
    updateDisplayString();
}

void PreemtingServer::endSendingPacket()
{
    EV_INFO << "Sending packet " << packet->getName() << " ended.\n";
    delete packet;
    packet = nullptr;
}

int PreemtingServer::getPriority(Packet *packet) const
{
    return packet->getTag<UserPriorityReq>()->getUserPriority();
}

void PreemtingServer::handleCanPushPacket(cGate *gate)
{
    Enter_Method("handleCanPushPacket");
    if (packet != nullptr)
        endSendingPacket();
    if (provider->canPopSomePacket(inputGate->getPathStartGate()))
        startSendingPacket();
}

void PreemtingServer::handleCanPopPacket(cGate *gate)
{
    Enter_Method("handleCanPopPacket");
    if (consumer->canPushSomePacket(outputGate->getPathEndGate()))
        startSendingPacket();
    else {
        auto nextPacket = provider->canPopPacket(inputGate->getPathStartGate());
        if (packet != nullptr && getPriority(nextPacket) > getPriority(packet)) {
            b confirmedLength = consumer->getPushedPacketConfirmedLength(packet, outputGate->getPathEndGate());
            b preemtedLength = roundingLength * ((confirmedLength + roundingLength - b(1)) / roundingLength);
            if (preemtedLength < packet->getTotalLength()) {
                // confirmed part
                const auto& confirmedPartSequenceNumberHeader = packet->peekAtFront<SequenceNumberHeader>();
                const auto& confirmedPartFragmentNumberHeader = packet->removeAtBack<FragmentNumberHeader>(B(1));
                const auto& remainingData = packet->removeAtBack(packet->getTotalLength() - preemtedLength);
                confirmedPartFragmentNumberHeader->setLastFragment(false);
                packet->insertAtBack(confirmedPartFragmentNumberHeader);
                auto fragmentTag = packet->addTagIfAbsent<FragmentTag>();
                fragmentTag->setFirstFragment(firstFragment);
                fragmentTag->setLastFragment(false);
                firstFragment = false;
                // remaining part
                std::string name = packet->getName();
                name = name.substr(0, name.rfind('-')) + "-frag" + std::to_string(confirmedPartFragmentNumberHeader->getFragmentNumber() + 1);
                Packet *remainingPart = new Packet(name.c_str(), remainingData);
                remainingPart->copyTags(*packet);
                remainingPart->setSchedulingPriority(-1);
                remainingPart->insertAtFront(confirmedPartSequenceNumberHeader);
                const auto& remainingPartFragmentNumberHeader = makeShared<FragmentNumberHeader>();
                remainingPartFragmentNumberHeader->setFragmentNumber(confirmedPartFragmentNumberHeader->getFragmentNumber() + 1);
                remainingPartFragmentNumberHeader->setLastFragment(true);
                remainingPart->insertAtBack(remainingPartFragmentNumberHeader);
                fragmentTag = remainingPart->addTag<FragmentTag>();
                fragmentTag->setFirstFragment(false);
                fragmentTag->setLastFragment(true);
                // send parts
                consumer->pushPacketProgress(packet, preemtedLength, packet->getTotalLength() - preemtedLength, outputGate->getPathEndGate());
                packet = nullptr;
                pushOrSendPacket(remainingPart, preemtedOutputGate, preemtedConsumer);
            }
        }
    }
}

} // namespace inet
