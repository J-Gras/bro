#include "NFLog.h"
#include "NetVar.h"

using namespace llanalyzer::NFLog;

NFLogAnalyzer::NFLogAnalyzer() : llanalyzer::Analyzer("NFLogAnalyzer") { }

NFLogAnalyzer::~NFLogAnalyzer() = default;

llanalyzer::identifier_t NFLogAnalyzer::analyze(Packet* packet) {
    auto pdata = packet->cur_pos;
    auto end_of_data = packet->GetEndOfData();

    // See https://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html

    identifier_t protocol = pdata[0];

    if ( protocol == AF_INET )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == AF_INET6 )
        packet->l3_proto = L3_IPV6;
    else
    {
        packet->Weird("non_ip_in_nflog");
        return NO_NEXT_LAYER;
    }

    uint8_t version = pdata[1];

    if ( version != 0 )
    {
        packet->Weird("unknown_nflog_version");
        return NO_NEXT_LAYER;
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
            return NO_NEXT_LAYER;
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
                return NO_NEXT_LAYER;
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
            return NO_NEXT_LAYER;
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
            return NO_NEXT_LAYER;
        }

    }

    // Calculate how much header we've used up.
    packet->hdr_size = (pdata - packet->data);

    return protocol;
}
