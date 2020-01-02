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
#include "inet/protocol/transceiver/Receiver.h"

namespace inet {

Define_Module(Receiver);

void Receiver::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        datarate = bps(par("datarate"));
        outputGate = gate("out");
        consumer = findConnectedModule<IPassivePacketSink>(outputGate);
    }
}

void Receiver::handleMessage(cMessage *message)
{
    if (message->isPacket())
        receiveSignal(check_and_cast<Signal *>(message));
    else
        throw cRuntimeError("Unknown message");
}

void Receiver::receiveSignal(Signal *signal)
{
    auto packet = check_and_cast<Packet *>(signal->decapsulate());
    // TODO: check signal physical properties such as datarate, modulation, etc.
    sendToUpperLayer(packet);
    delete signal;
}

void Receiver::sendToUpperLayer(Packet *packet)
{
    pushOrSendPacket(packet, outputGate, consumer);
}

} // namespace inet
