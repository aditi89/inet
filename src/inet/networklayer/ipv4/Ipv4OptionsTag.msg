//
// This program is property of its copyright holder. All rights reserved.
//

import inet.common.INETDefs;
import inet.common.TagBase;
import inet.networklayer.ipv4.Ipv4Header;

namespace inet;

class Ipv4OptionsTagBase extends TagBase
{
    Ipv4Option *option[] @owned;
}

//
// Determines the source and destination network addresses for an outgoing packet.
//
class Ipv4OptionsReq extends Ipv4OptionsTagBase
{
}

//
// Specifies the source and destination network addresses for an incoming packet.
//
class Ipv4OptionsInd extends Ipv4OptionsTagBase
{
}

