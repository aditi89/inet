//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include <errno.h>
#include "inet/common/DirectionTag_m.h"
#include "inet/common/INETUtils.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/packet/recorder/PcapngWriter.h"

namespace inet {

#define PCAP_MAGIC      0x1a2b3c4d

struct pcapng_option_header
{
    uint16_t code;
    uint16_t length;
};

struct pcapng_section_block_header
{
    uint32_t blockType = 0x0A0D0D0A;
    uint32_t blockTotalLength;
    uint32_t byteOrderMagic;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint64_t sectionLength;
};

struct pcapng_section_block_trailer
{
    uint32_t blockTotalLength;
};

struct pcapng_interface_block_header
{
    uint32_t blockType = 0x00000001;
    uint32_t blockTotalLength;
    uint16_t linkType;
    uint16_t reserved;
    uint32_t snaplen;
};

struct pcapng_interface_block_trailer
{
    uint32_t blockTotalLength;
};

struct pcapng_packet_block_header
{
    uint32_t blockType = 0x00000006;
    uint32_t blockTotalLength;
    uint32_t interfaceId;
    uint32_t timestampHigh;
    uint32_t timestampLow;
    uint32_t capturedPacketLength;
    uint32_t originalPacketLength;
};

struct pcapng_packet_block_trailer
{
    uint32_t blockTotalLength;
};

PcapngWriter::~PcapngWriter()
{
    closePcap();
}

void PcapngWriter::openPcap(const char *filename, unsigned int snaplen, uint32_t linkType)
{
    if (!filename || !filename[0])
        throw cRuntimeError("Cannot open pcap file: file name is empty");

    inet::utils::makePathForFile(filename);
    dumpfile = fopen(filename, "wb");
    this->linkType = linkType;

    if (!dumpfile)
        throw cRuntimeError("Cannot open pcap file [%s] for writing: %s", filename, strerror(errno));

    flush = false;

    struct pcapng_section_block_header sbh;
    sbh.blockTotalLength = 28;
    sbh.byteOrderMagic = PCAP_MAGIC;
    sbh.majorVersion = 1;
    sbh.minorVersion = 0;
    sbh.sectionLength = -1L;
    fwrite(&sbh, sizeof(sbh), 1, dumpfile);

    struct pcapng_section_block_trailer sbt;
    sbt.blockTotalLength = 28;
    fwrite(&sbt, sizeof(sbt), 1, dumpfile);
}

void PcapngWriter::writeInterface(InterfaceEntry *interfaceEntry)
{
    if (!dumpfile)
        throw cRuntimeError("Cannot write interface: pcap output file is not open");

    EV << "PcapngWriter::writeInterface()\n";
    uint32_t optionsLength = 0;

    pcapng_interface_block_header ibh;
    ibh.blockTotalLength = 20 + optionsLength;
    ibh.linkType = linkType;
    ibh.reserved = 0;
    ibh.snaplen = 0;
    fwrite(&ibh, sizeof(ibh), 1, dumpfile);

    pcapng_interface_block_trailer ibt;
    ibt.blockTotalLength = 20 + optionsLength;
    fwrite(&ibt, sizeof(ibt), 1, dumpfile);
}

void PcapngWriter::writePacket(simtime_t stime, const Packet *packet)
{
    if (!dumpfile)
        throw cRuntimeError("Cannot write frame: pcap output file is not open");

    auto interfaceEntry = getContainingNicModule(check_and_cast<cModule *>(packet->getOwner()));
    auto it = interfaceModuleIdToInterfaceId.find(interfaceEntry->getId());
    int interfaceId;
    if (it != interfaceModuleIdToInterfaceId.end())
        interfaceId = it->second;
    else {
        writeInterface(interfaceEntry);
        interfaceId = nextInterfaceId++;
        interfaceModuleIdToInterfaceId[interfaceEntry->getId()] = interfaceId;
    }

    EV << "PcapngWriter::writePacket()\n";
    uint32_t optionsLength = 12;

    struct pcapng_packet_block_header pbh;
    pbh.blockTotalLength = 32 + packet->getByteLength() + optionsLength;
    pbh.interfaceId = interfaceId;
    pbh.timestampHigh = (int32_t)stime.inUnit(SIMTIME_S);
    pbh.timestampLow = (uint32_t)(stime.inUnit(SIMTIME_US) - (uint32_t)1000000 * stime.inUnit(SIMTIME_S));
    pbh.capturedPacketLength = packet->getByteLength();
    pbh.originalPacketLength = packet->getByteLength();
    fwrite(&pbh, sizeof(pbh), 1, dumpfile);

    auto data = packet->peekDataAsBytes();
    auto bytes = data->getBytes();
    fwrite(bytes.data(), packet->getByteLength(), 1, dumpfile);

    char padding[] = {0, 0, 0, 0};
    int paddingLength = (4 - packet->getByteLength() % 4) % 4;
    fwrite(padding, paddingLength, 1, dumpfile);

    pcapng_option_header doh;
    doh.code = 0x0002;
    doh.length = 4;
    auto directionTag =packet->findTag<DirectionTag>();
    uint32_t flagsOptionValue = directionTag == nullptr ? 00 : directionTag->getInbound() ? 0b01 : 0b10;
    fwrite(&doh, sizeof(doh), 1, dumpfile);
    fwrite(&flagsOptionValue, sizeof(flagsOptionValue), 1, dumpfile);

    uint32_t endOfOptions = 0;
    fwrite(&endOfOptions, sizeof(endOfOptions), 1, dumpfile);

    struct pcapng_packet_block_trailer pbt;
    pbt.blockTotalLength = 32 + packet->getByteLength() + optionsLength;
    fwrite(&pbt, sizeof(pbt), 1, dumpfile);

    if (flush)
        fflush(dumpfile);
}

void PcapngWriter::closePcap()
{
    if (dumpfile) {
        fclose(dumpfile);
        dumpfile = nullptr;
    }
}

} // namespace inet

