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
#include "inet/protocol/transceiver/StartStopReceiver.h"

namespace inet {

Define_Module(StartStopReceiver);

void StartStopReceiver::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        dataratePar = &par("datarate");
        inputGate = gate("in");
        outputGate = gate("out");
        consumer = findConnectedModule<IPassivePacketSink>(outputGate);
    }
}

StartStopReceiver::~StartStopReceiver()
{
    delete rxSignal;
}

void StartStopReceiver::handleMessage(cMessage *message)
{
    if (message->getArrivalGate() == inputGate)
        receiveFromMedium(message);
    else
        throw cRuntimeError("Unknown message");
}

void StartStopReceiver::sendToUpperLayer(Packet *packet)
{
    pushOrSendPacket(packet, outputGate, consumer);
}

void StartStopReceiver::receivePacketStart(cPacket *cpacket)
{
    ASSERT(rxSignal == nullptr);
    take(cpacket);
    rxSignal = check_and_cast<Signal *>(cpacket);
}

void StartStopReceiver::receivePacketProgress(cPacket *cpacket, int bitPosition, simtime_t timePosition, int extraProcessableBitLength, simtime_t extraProcessableDuration)
{
    take(cpacket);
    delete rxSignal;
    rxSignal = check_and_cast<Signal *>(cpacket);
}

void StartStopReceiver::receivePacketEnd(cPacket *cpacket)
{
    delete rxSignal;
    rxSignal = check_and_cast<Signal *>(cpacket);
    auto packet = check_and_cast<Packet *>(rxSignal->decapsulate());
    sendToUpperLayer(packet);
    delete rxSignal;
    rxSignal = nullptr;
}

} // namespace inet
