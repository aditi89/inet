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

#ifndef __INET_FRAGMENTERBASE_H
#define __INET_FRAGMENTERBASE_H

#include "inet/protocol/common/HeaderPosition.h"
#include "inet/queueing/base/PacketPusherBase.h"

namespace inet {

using namespace inet::queueing;

class INET_API FragmenterBase : public PacketPusherBase
{
  protected:
    HeaderPosition headerPosition = HP_UNDEFINED;

  protected:
    virtual void initialize(int stage) override;

    virtual std::vector<b> computeFragmentLengths(Packet *packet) const = 0;

  public:
    virtual void pushPacket(Packet *packet, cGate *gate) override;
};

} // namespace inet

#endif // ifndef __INET_FRAGMENTERBASE_H

