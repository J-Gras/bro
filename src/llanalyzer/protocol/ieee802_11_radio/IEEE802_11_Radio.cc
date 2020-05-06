#include "IEEE802_11_Radio.h"
#include "NetVar.h"

using namespace llanalyzer::IEEE802_11_Radio;

IEEE802_11_RadioAnalyzer::IEEE802_11_RadioAnalyzer() : llanalyzer::Analyzer("IEEE802_11_RadioAnalyzer"), protocol(0), currentPacket(nullptr) {
}

IEEE802_11_RadioAnalyzer::~IEEE802_11_RadioAnalyzer() = default;

uint32_t IEEE802_11_RadioAnalyzer::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    //protocol = (packet->cur_pos[12] << 8u) + packet->cur_pos[13];
    return protocol;
}

void IEEE802_11_RadioAnalyzer::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    const u_char *pdata = packet->data;
    const u_char *end_of_data = packet->data + packet->cap_len;

    if ( pdata + 3 >= end_of_data )
    {
        packet->Weird("truncated_radiotap_header");
        return;
    }

    // Skip over the RadioTap header
    int rtheader_len = (pdata[3] << 8) + pdata[2];

    if ( pdata + rtheader_len >= end_of_data )
    {
        packet->Weird("truncated_radiotap_header");
        return;
    }

    packet->cur_pos += rtheader_len;

    protocol = 105;
    //currentPacket = nullptr;
}
