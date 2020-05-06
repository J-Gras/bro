#include "NFLog.h"
#include "NetVar.h"

using namespace llanalyzer::NFLog;

NFLogAnalyzer::NFLogAnalyzer() : llanalyzer::Analyzer("NFLogAnalyzer"), protocol(0), currentPacket(nullptr) {
}

NFLogAnalyzer::~NFLogAnalyzer() = default;

uint32_t NFLogAnalyzer::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    //protocol = (packet->cur_pos[12] << 8u) + packet->cur_pos[13];
    return protocol;
}

void NFLogAnalyzer::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    const u_char *pdata = packet->data;
    const u_char *end_of_data = packet->data + packet->cap_len;

    // See https://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html

    protocol = pdata[0];

    if ( protocol == AF_INET )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == AF_INET6 )
        packet->l3_proto = L3_IPV6;
    else
    {
        packet->Weird("non_ip_in_nflog");
        return;
    }

    uint8_t version = pdata[1];

    if ( version != 0 )
    {
        packet->Weird("unknown_nflog_version");
        return;
    }

    // Skip to TLVs.
    pdata += 4;

    uint16_t tlv_len;
    uint16_t tlv_type;

    while ( true )
    {
        if ( pdata + 4 >= end_of_data )
        {
            packet->Weird("nflog_no_pcap_payload");
            return;
        }

        // TLV Type and Length values are specified in host byte order
        // (libpcap should have done any needed byteswapping already).

        tlv_len = *(reinterpret_cast<const uint16_t*>(pdata));
        tlv_type = *(reinterpret_cast<const uint16_t*>(pdata + 2));

        auto constexpr nflog_type_payload = 9;

        if ( tlv_type == nflog_type_payload )
        {
            // The raw packet payload follows this TLV.
            pdata += 4;
            break;
        }
        else
        {
            // The Length value includes the 4 octets for the Type and
            // Length values, but TLVs are also implicitly padded to
            // 32-bit alignments (that padding may not be included in
            // the Length value).

            if ( tlv_len < 4 )
            {
                packet->Weird("nflog_bad_tlv_len");
                return;
            }
            else
            {
                auto rem = tlv_len % 4;

                if ( rem != 0 )
                    tlv_len += 4 - rem;
            }

            pdata += tlv_len;
        }
    }

   if (encap_hdr_size) {
        // Blanket encapsulation. We assume that what remains is IP.
        if (pdata + encap_hdr_size + sizeof(struct ip) >= end_of_data) {
            packet->Weird("no_ip_left_after_encap");
            return;
        }

        pdata += encap_hdr_size;

        const struct ip *ip = (const struct ip *) pdata;

        if (ip->ip_v == 4)
            packet->l3_proto = L3_IPV4;
        else if (ip->ip_v == 6)
            packet->l3_proto = L3_IPV6;
        else {
            // Neither IPv4 nor IPv6.
            packet->Weird("no_ip_in_encap");
            return;
        }

    }

    // We've now determined (a) L3_IPV4 vs (b) L3_IPV6 vs (c) L3_ARP vs
    // (d) L3_UNKNOWN.

    // Calculate how much header we've used up.
    packet->hdr_size = (pdata - packet->data);

    protocol = 0;
    currentPacket = nullptr;
}
