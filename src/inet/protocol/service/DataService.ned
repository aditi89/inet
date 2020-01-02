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

package inet.protocol.service;

import inet.protocol.aggregation.Aggregation;
import inet.protocol.aggregation.Deaggregation;
import inet.protocol.fragmentation.Defragmenter;
import inet.protocol.fragmentation.FixedLengthFragmenter;
import inet.protocol.ordering.Reordering;
import inet.protocol.ordering.SequenceNumbering;
import inet.queueing.contract.IPacketQueue;
import inet.queueing.contract.IPacketServer;

module DataService
{
    parameters:
        @display("i=block/layer");
    gates:
        input upperLayerIn;
        output upperLayerOut;
        input lowerLayerIn;
        output lowerLayerOut;
    submodules:
        aggregation: Aggregation {
            @display("p=150,100");
        }
        fragmenter: FixedLengthFragmenter {
            @display("p=150,200");
        }
        sequenceNumbering: SequenceNumbering {
            @display("p=150,300");
        }
        queue: <default("DropTailQueue")> like IPacketQueue {
            @display("p=150,400");
        }
        server: <default("PacketServer")> like IPacketServer {
            @display("p=150,500");
        }
        deaggregation: Deaggregation {
            @display("p=450,100");
        }
        defragmenter: Defragmenter {
            @display("p=450,200");
        }
        reordering: Reordering {
            @display("p=450,300");
        }
    connections:
        upperLayerIn --> { @display("m=n"); } --> aggregation.in;
        aggregation.out --> fragmenter.in;
        fragmenter.out --> sequenceNumbering.in;
        sequenceNumbering.out --> queue.in;
        queue.out --> server.in;
        server.out --> { @display("m=s"); } --> lowerLayerOut;
        lowerLayerIn --> { @display("m=s"); } --> reordering.in;
        reordering.out --> defragmenter.in;
        defragmenter.out --> deaggregation.in;
        deaggregation.out --> { @display("m=n"); } --> upperLayerOut;
}
