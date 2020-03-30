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
import inet.protocol.Padding;
import inet.protocol.transceiver.PreemtableTransmitter;
import inet.protocol.transceiver.StartStopReceiver;
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
                @display("p=238,470");
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
                @display("p=148,1245");
        }
        transmitter: PreemtableTransmitter {
            parameters:
                @display("p=148,1361");
        }
        typeOrLengthChecking: TypeOrLengthChecking {
            parameters:
                @display("p=565,71");
        }
        addressChecking: AddressChecking {
            parameters:
                @display("p=565,171");
        }
        fcsVerification: EthernetFcsVerification {
            parameters:
                @display("p=457,896");
        }
        preambleChecker: PreambleChecker {
            parameters:
                @display("p=457,1090");
        }
        receiver: StartStopReceiver {
            parameters:
                @display("p=565,1400");
        }
        fcsInsertion1: FragmentFcsInsertion {
            parameters:
                @display("p=238,852");
        }
        preambleInsertion1: FragmentPreambleInsertion {
            parameters:
                @display("p=238,952");
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
        preemptingServer: EthernetPreemptingServer {
            @display("p=187,630");
        }
        classifier2: PacketClassifier {
            @display("p=165,737");
        }
        defragmentation: EthernetDefragmentation {
            @display("p=644,898");
        }
        preambleClassifier: PacketClassifier {
            @display("p=565,1188");
        }
        fcsVerification1: FragmentFcsVerification {
            parameters:
                @display("p=644,999");
        }
        preambleChecker1: FragmentPreambleChecker {
            parameters:
                @display("p=644,1092");
        }
        packetMultiplexer1: PacketMultiplexer {
            @display("p=565,776");
        }
        xxx: Xxx {
            @display("p=148,1143");
        }
        xxx1: Xxx {
            @display("p=565,1290");
        }
    connections:
        typeOrLengthInsertion.out --> addressInsertion.in;
        fcsInsertion.out --> preambleInsertion.in;
        transmitter.out --> phys$o;
        phys$i --> receiver.in;
        preambleChecker.out --> fcsVerification.in;
        addressChecking.out --> typeOrLengthChecking.in;
        typeOrLengthChecking.out --> upperLayerOut;
        fcsInsertion1.out --> preambleInsertion1.in;
        preambleInsertion.out --> packetMultiplexer.in++;
        preambleInsertion1.out --> packetMultiplexer.in++;
        expressQueue.out --> priorityScheduler.in++;
        remainingQueue.out --> priorityScheduler.in++;
        upperLayerIn --> typeOrLengthInsertion.in;
        normalQueue.out --> priorityScheduler.in++;
        priorityScheduler.out --> preemptingServer.in;
        preemptingServer.preemtedOut --> remainingQueue.in;
        classifier1.out++ --> normalQueue.in;
        classifier1.out++ --> expressQueue.in;
        preemptingServer.out --> classifier2.in;
        addressInsertion.out --> padding.in;
        padding.out --> classifier1.in;
        classifier2.out++ --> fcsInsertion1.in;
        classifier2.out++ --> fcsInsertion.in;
        preambleChecker1.out --> fcsVerification1.in;
        fcsVerification1.out --> defragmentation.in;
        defragmentation.out --> packetMultiplexer1.in++;
        fcsVerification.out --> packetMultiplexer1.in++;
        packetMultiplexer1.out --> addressChecking.in;
        ifg.out --> transmitter.in;
        preambleClassifier.out++ --> preambleChecker.in;
        preambleClassifier.out++ --> preambleChecker1.in;
        packetMultiplexer.out --> xxx.in;
        xxx.out --> ifg.in;
        receiver.out --> xxx1.in;
        xxx1.out --> preambleClassifier.in;
}
