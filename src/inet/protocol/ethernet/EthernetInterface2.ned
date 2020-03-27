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

package inet.protocol.ethernet;

import inet.common.MessageDispatcher;
import inet.protocol.PreemptingServer;
import inet.protocol.checksum.FcsInsertion;
import inet.protocol.checksum.FcsVerification;
import inet.protocol.fragmentation.Defragmentation;
import inet.protocol.queue.InProgressQueue;
import inet.protocol.transceiver.PreemtableTransmitter;
import inet.protocol.transceiver.Receiver;
import inet.queueing.classifier.PacketClassifier;
import inet.queueing.common.PacketCloner;
import inet.queueing.common.PacketMultiplexer;
import inet.queueing.queue.PacketQueue;
import inet.queueing.server.InstantServer;


simple SocketTable
{
    @display("i=block/table");
}

simple SocketX
{
    @display("i=block/cogwheel");
    gates:
        input in;
        output out;
}

simple SocketY
{
    @display("i=block/cogwheel");
    gates:
        input in;
        output out;
}

simple LlcX
{
    gates:
        input in;
        output out;
}

simple QTagger
{
    gates:
        input in;
        output out;
}

simple ConnectionX
{
    gates:
        input in;
        output out;
}

simple PauseX
{
    gates:
        input in;
        output out;
}

simple PauseY
{
    gates:
        input in;
        output out;
}

module EthernetInterface2
{
    parameters:
        @display("i=block/ifcard");
    gates:
        input upperLayerIn;
        output upperLayerOut;
        input physicalIn;
        output physicalOut;
    submodules:
        socketTable: SocketTable {
            parameters:
                @display("p=100,100");
        }
        multiplexer: PacketMultiplexer {
            parameters:
                @display("p=450,100");
        }
        dispatcher: MessageDispatcher {
            parameters:
                @display("p=250,100");
        }
        pauseX: PauseX {
            parameters:
                @display("p=250,200");
        }
        llcInsertion: LlcX {
            parameters:
                @display("p=150,200");
        }
        multiplexerQ: PacketMultiplexer {
            parameters:
                @display("p=150,300");
        }
        pendingQueue: PacketQueue {
            parameters:
                @display("p=150,400");
        }
        instantServer: InstantServer {
            parameters:
                @display("p=150,500");
        }
        socketX: SocketX {
            parameters:
                @display("p=350,200");
        }
        socketY: SocketY {
            parameters:
                @display("p=550,200");
        }
        addressInsertion: AddressInsertion {
            parameters:
                @display("p=150,600");
        }
        qOrAndAeTagger: QTagger {
            parameters:
                @display("p=150,700");
        }
        cloner: PacketCloner {
            parameters:
                @display("p=450,300");
        }
        multiplexer3: PacketMultiplexer {
            parameters:
                @display("p=200,800");
        }
        inProgressQueue: InProgressQueue {
            parameters:
                @display("p=100,900");
        }
        preemptingServer: PreemptingServer {
            parameters:
                @display("p=200,1000");
        }
        fcsInsertion: FcsInsertion {
            parameters:
                @display("p=150,1100");
        }
        preambleInsertion: PreambleInsertion {
            parameters:
                @display("p=150,1200");
        }
        preemptableTransmitter: PreemtableTransmitter {
            parameters:
                @display("p=150,1300");
        }
        connectionX: ConnectionX {
            parameters:
                @display("p=150,1400");
        }
        multiplexer2: PacketMultiplexer {
            parameters:
                @display("p=450,600");
        }
        defragmentation: Defragmentation {
            parameters:
                @display("p=550,700");
        }
        classifier: PacketClassifier {
            parameters:
                @display("p=450,800");
        }
        pauseY: PauseY {
            parameters:
                @display("p=350,700");
        }
        addressChecking: AddressChecking {
            parameters:
                @display("p=450,900");
        }
        fcsVerification: FcsVerification {
            parameters:
                @display("p=450,1000");
        }
        receiver: Receiver {
            parameters:
                @display("p=450,1400");
        }
    connections:
        upperLayerIn --> dispatcher.in++;
        dispatcher.out++ --> llcInsertion.in;
        dispatcher.out++ --> socketX.in;
        dispatcher.out++ --> pauseX.in;
        pauseX.out --> multiplexerQ.in++;
        llcInsertion.out --> multiplexerQ.in++;
        multiplexerQ.out --> pendingQueue.in;
        pendingQueue.out --> instantServer.in;
        instantServer.out --> addressInsertion.in;
        addressInsertion.out --> qOrAndAeTagger.in;
        qOrAndAeTagger.out --> multiplexer3.in++;
        multiplexer3.out --> inProgressQueue.in;
        inProgressQueue.out --> preemptingServer.in;
        preemptingServer.out --> fcsInsertion.in;
        preemptingServer.preemtedOut --> multiplexer3.in++;
        fcsInsertion.out --> preambleInsertion.in;
        preambleInsertion.out --> preemptableTransmitter.in;
        preemptableTransmitter.out --> connectionX.in;
        connectionX.out --> physicalOut;

        physicalIn --> receiver.in;
        receiver.out --> fcsVerification.in;
        fcsVerification.out --> addressChecking.in;
        addressChecking.out --> classifier.in;
        classifier.out++ --> defragmentation.in;
        classifier.out++ --> multiplexer2.in++;
        classifier.out++ --> pauseY.in;
        defragmentation.out --> multiplexer2.in++;
        multiplexer2.out --> cloner.in;
        socketY.out --> multiplexer.in++;
        cloner.out++ --> socketY.in;
        cloner.out++ --> multiplexer.in++;
        multiplexer.out --> upperLayerOut;
}
