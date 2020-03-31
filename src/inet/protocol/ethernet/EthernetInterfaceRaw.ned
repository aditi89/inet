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
import inet.protocol.PacketTrimmer;
import inet.protocol.Padding;
import inet.protocol.transceiver.StartStopReceiver;
import inet.protocol.transceiver.StartStopTransmitter;
import inet.queueing.queue.PacketQueue;
import inet.queueing.server.InstantServer;

module EthernetInterfaceRaw extends InterfaceEntry like IEthernetInterface
{
    parameters:
        string interfaceTableModule;
        string address = default("auto");
        bool broadcast = default(true);
        bool multicast = default(true);
        bool promiscuous = default(false);  // if true, all packets are received, otherwise only the
                                            // ones with matching destination MAC address
        double bitrate @unit(bps) = default(nan bps);
        int mtu @unit(B) = default(1500B);
        string fcsMode @enum("declared","computed") = default("declared");
        @class(InterfaceEntry);
        @display("i=block/ifcard");
        padding.minLength = 60B;
        ifg.duration = 96s/dropUnit(bitrate);
        transmitter.datarate = bitrate;
        receiver.datarate = bitrate;
        addressChecking.promiscuous = promiscuous;
    gates:
        input upperLayerIn;
        output upperLayerOut;
        inout phys;
    submodules:
        queue: PacketQueue {
            parameters:
                @display("p=150,100");
        }
        server: InstantServer {
            parameters:
                @display("p=150,200");
        }
        fcsVerification1: EthernetFcsVerification {
            parameters:
                @display("p=150,300");
        }
        packetTrimmer: PacketTrimmer {
            @display("p=150,400");
        }
        padding: Padding {
            parameters:
                @display("p=150,500");
        }
        fcsInsertion: EthernetFcsInsertion {
            parameters:
                @display("p=150,600");
        }
        preambleInsertion: PreambleInsertion {
            parameters:
                @display("p=150,700");
        }
        serializer: PacketSerializer {
            parameters:
                @display("p=150,800");
        }
        ifg: InterPacketGap {
            parameters:
                @display("p=150,900");
        }
        transmitter: StartStopTransmitter {
            parameters:
                @display("p=150,1000");
        }
        fcsVerification: EthernetFcsVerification2 {
            parameters:
                @display("p=450,600");
        }
        preambleChecker: PreambleChecker {
            parameters:
                @display("p=450,800");
        }
        receiver: StartStopReceiver {
            parameters:
                @display("p=450,1000");
        }
        channelDatarateReader: ChannelDatarateReader {
            @display("p=301,1000");
        }
    connections:
        upperLayerIn --> queue.in;
        queue.out --> server.in;
        server.out --> fcsVerification1.in;
        fcsVerification1.out --> packetTrimmer.in;
        packetTrimmer.out --> padding.in;
        padding.out --> fcsInsertion.in;
        fcsInsertion.out --> preambleInsertion.in;
        preambleInsertion.out --> serializer.in;
        serializer.out --> ifg.in;
        ifg.out --> transmitter.in;
        transmitter.out --> phys$o;
        phys$i --> receiver.in;
        receiver.out --> preambleChecker.in;
        preambleChecker.out --> fcsVerification.in;
        fcsVerification.out --> { @display("m=n"); } --> upperLayerOut;
}

