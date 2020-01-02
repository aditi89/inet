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

#ifndef __INET_FIXEDLENGTHFRAGMENTER_H
#define __INET_FIXEDLENGTHFRAGMENTER_H

#include "inet/protocol/fragmentation/FragmenterBase.h"

namespace inet {

using namespace inet::queueing;

class INET_API FixedLengthFragmenter : public FragmenterBase
{
  protected:
    b maxFragmentLength = b(-1);
    b fragmentHeaderLength = b(-1);

  protected:
    virtual void initialize(int stage) override;

    virtual std::vector<b> computeFragmentLengths(Packet *packet) const override;
};

} // namespace inet

#endif // ifndef __INET_FIXEDLENGTHFRAGMENTER_H

