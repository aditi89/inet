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

#ifndef __INET_IPASSIVEPACKETSOURCE_H
#define __INET_IPASSIVEPACKETSOURCE_H

#include "inet/common/packet/Packet.h"

namespace inet {
namespace queueing {

/**
 * This class defines the interface for passive packet sources.
 * See the corresponding NED file for more details.
 */
class INET_API IPassivePacketSource
{
  public:
    enum CanPopSomePacketResult {
        POP_NONE = 0,
        POP_ANY  = 1,
        POP_SOME = 2,
    };

  public:
    virtual ~IPassivePacketSource() {}

    // TODO: rename these to pull*
    /**
     * Returns false if the packet source is empty at the given gate and no more
     * packets can be popped from it without raising an error. The gate must
     * support popping packets.
     */
    // TODO: change name and result to: ANY, SOME, NONE
    virtual bool canPopSomePacket(cGate *gate = nullptr) const = 0;

    /**
     * Returns the packet that can be popped at the given gate. The returned
     * value may be nullptr if there is no such packet. The gate must support
     * popping packets.
     */
    virtual Packet *canPopPacket(cGate *gate = nullptr) const = 0;

    /**
     * Pops a packet from the packet source at the given gate. This operation
     * pops the packet all at once. The source must not be empty at the given
     * gate. The returned packet is never nullptr, and the gate must support
     * popping packets.
     */
    virtual Packet *popPacket(cGate *gate = nullptr) = 0;

    /**
     * Starts pulling the packet from the packet source at the given gate. This is
     * a streaming operation. The source must not be empty at the gate. The gate
     * must support pulling packets and the returned packet is never nullptr.
     */
    virtual Packet *pullPacketStart(cGate *gate = nullptr) = 0;

    /**
     * Ends pulling the packet from the packet source at the given gate. This is
     * a streaming operation. The source must not be empty at the gate. The gate
     * must support pulling packets and the returned packet is never nullptr.
     */
    virtual Packet *pullPacketEnd(cGate *gate = nullptr) = 0;

    /**
     * Progresses pulling the packet from the packet source at the given gate.
     * This is a streaming operation. The position specifies where the streaming
     * is at the moment. The extra length partially fixes the future of the
     * streaming operation. The source must not be empty at the gate. The gate
     * must support pulling packets and the returned packet is never nullptr.
     */
    virtual Packet *pullPacketProgress(b& position, b& extraProcessableLength, cGate *gate = nullptr) = 0;

    /**
     * TODO
     */
    virtual b getPulledPacketConfirmedLength(Packet *packet, cGate *gate = nullptr) = 0;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_IPASSIVEPACKETSOURCE_H

