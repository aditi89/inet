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

#ifndef __INET_FRAGMENTPREAMBLEINSERTION_H
#define __INET_FRAGMENTPREAMBLEINSERTION_H

#include "inet/queueing/base/PacketFlowBase.h"

namespace inet {

using namespace inet::queueing;

class INET_API FragmentPreambleInsertion : public PacketFlowBase
{
  protected:
    int SMD_Sx[4] = {0xE6, 0x4C, 0x7F, 0xB3};
    int SMD_Cx[4] = {0x61, 0x52, 0x9E, 0x2A};
    int fragmentIndex = 0;
    int fragmentCount = 0;

  protected:
    virtual void initialize(int stage) override;

  public:
    virtual void processPacket(Packet *packet) override;
};

} // namespace inet

#endif // ifndef __INET_FRAGMENTPREAMBLEINSERTION_H

