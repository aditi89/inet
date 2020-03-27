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

import inet.linklayer.contract.IEthernetInterface;
import inet.networklayer.common.InterfaceEntry;
import inet.protocol.InterPacketGap;
import inet.protocol.PacketSerializer;
import inet.protocol.Padding;
import inet.protocol.PreemtingServer;
import inet.protocol.fragmentation.Defragmentation;
import inet.protocol.transceiver.StartStopReceiver;
import inet.protocol.transceiver.StartStopTransmitter;
import inet.queueing.classifier.PacketClassifier;
import inet.queueing.common.PacketMultiplexer;
import inet.queueing.queue.PacketQueue;
import inet.queueing.scheduler.PriorityScheduler;

module EthernetInterfaceP extends InterfaceEntry like IEthernetInterface
{
    parameters:
        bool broadcast = default(true);
        bool multicast = default(true);
        string address = default("auto");
        double bitrate @unit(bps);
        string interfaceTableModule;
        @class(InterfaceEntry);
        @display("i=block/ifcard");
    gates:
        input upperLayerIn;
        output upperLayerOut;
        inout phys;
    submodules:
        remainingQueue: PacketQueue {
            parameters:
                @display("p=226,470");
        }
        typeOrLengthInsertion: TypeOrLengthInsertion {
            parameters:
                @display("p=187,71");
        }
        addressInsertion: AddressInsertion {
            parameters:
                @display("p=187,171");
        }
        padding: Padding {
            parameters:
                @display("p=187,285");
        }
        fcsInsertion: EthernetFcsInsertion {
            parameters:
                @display("p=91,852");
        }
        preambleInsertion: PreambleInsertion {
            parameters:
                @display("p=91,952");
        }
        ifg: InterPacketGap {
            parameters:
                @display("p=148,1161");
        }
        serializer: PacketSerializer {
            parameters:
                @display("p=148,1261");
        }
        transmitter: StartStopTransmitter {
            parameters:
                @display("p=148,1361");
        }
        typeOrLengthChecking: TypeOrLengthChecking {
            parameters:
                @display("p=548,71");
        }
        addressChecking: AddressChecking {
            parameters:
                @display("p=548,171");
        }
        fcsVerification: EthernetFcsVerification {
            parameters:
                @display("p=661,1013");
        }
        preambleChecker: PreambleChecker {
            parameters:
                @display("p=661,1222");
        }
        receiver: StartStopReceiver {
            parameters:
                @display("p=548,1400");
        }
        fcsInsertion1: FragmentFcsInsertion {
            parameters:
                @display("p=258,852");
        }
        preambleInsertion1: FragmentPreambleInsertion {
            parameters:
                @display("p=252,952");
        }
        packetMultiplexer: PacketMultiplexer {
            @display("p=148,1052");
        }
        expressQueue: PacketQueue {
            parameters:
                @display("p=70,470");
        }
        priorityScheduler: PriorityScheduler {
            @display("p=109,561");
        }
        classifier1: PacketClassifier {
            @display("p=187,390");
        }
        normalQueue: PacketQueue {
            parameters:
                @display("p=384,470");
        }
        preemtingServer: PreemtingServer {
            @display("p=187,630");
        }
        classifier2: PacketClassifier {
            @display("p=187,738");
        }
        defragmentation: Defragmentation {
            @display("p=468,1013");
        }
        classifier3: PacketClassifier {
            @display("p=548,1322");
        }
        fcsVerification1: FragmentFcsVerification {
            parameters:
                @display("p=468,1114");
        }
        preambleChecker1: FragmentPreambleChecker {
            parameters:
                @display("p=468,1222");
        }
        packetMultiplexer1: PacketMultiplexer {
            @display("p=565,899");
        }
    connections:
        typeOrLengthInsertion.out --> addressInsertion.in;
        fcsInsertion.out --> preambleInsertion.in;
        ifg.out --> serializer.in;
        serializer.out --> transmitter.in;
        transmitter.out --> phys$o;
        phys$i --> receiver.in;
        preambleChecker.out --> fcsVerification.in;
        addressChecking.out --> typeOrLengthChecking.in;
        typeOrLengthChecking.out --> upperLayerOut;
        fcsInsertion1.out --> preambleInsertion1.in;
        preambleInsertion.out --> packetMultiplexer.in++;
        preambleInsertion1.out --> packetMultiplexer.in++;
        packetMultiplexer.out --> ifg.in;
        classifier1.out++ --> expressQueue.in;
        expressQueue.out --> priorityScheduler.in++;
        remainingQueue.out --> priorityScheduler.in++;
        upperLayerIn --> typeOrLengthInsertion.in;
        normalQueue.out --> priorityScheduler.in++;
        priorityScheduler.out --> preemtingServer.in;
        preemtingServer.preemtedOut --> remainingQueue.in;
        classifier1.out++ --> normalQueue.in;
        preemtingServer.out --> classifier2.in;
        addressInsertion.out --> padding.in;
        padding.out --> classifier1.in;
        classifier2.out++ --> fcsInsertion.in;
        classifier2.out++ --> fcsInsertion1.in;
        preambleChecker1.out --> fcsVerification1.in;
        receiver.out --> classifier3.in;
        classifier3.out++ --> preambleChecker1.in;
        fcsVerification1.out --> defragmentation.in;
        classifier3.out++ --> preambleChecker.in;
        defragmentation.out --> packetMultiplexer1.in++;
        fcsVerification.out --> packetMultiplexer1.in++;
        packetMultiplexer1.out --> addressChecking.in;
}
