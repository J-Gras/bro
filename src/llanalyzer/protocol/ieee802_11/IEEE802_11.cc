#include "IEEE802_11.h"
#include "NetVar.h"

using namespace llanalyzer::IEEE802_11;

IEEE802_11Analyzer::IEEE802_11Analyzer() : llanalyzer::Analyzer("IEEE802_11Analyzer"), protocol(0), currentPacket(nullptr) {
}

IEEE802_11Analyzer::~IEEE802_11Analyzer() = default;

uint32_t IEEE802_11Analyzer::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    //protocol = (packet->cur_pos[0] << 8) + packet->cur_pos[1];
    return protocol;
}

void IEEE802_11Analyzer::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }
    const u_char *pdata = packet->cur_pos;
    const u_char *end_of_data = packet->data + packet->cap_len;

    u_char len_80211 = 24; // minimal length of data frames

    if ( pdata + len_80211 >= end_of_data )
    {
        packet->Weird("truncated_802_11_header");
        return;
    }

    u_char fc_80211 = pdata[0]; // Frame Control field

    // Skip non-data frame types (management & control).
    if ( ! ((fc_80211 >> 2) & 0x02) )
        return;

    // Skip subtypes without data.
    if ( (fc_80211 >> 4) & 0x04 )
        return;

    // 'To DS' and 'From DS' flags set indicate use of the 4th
    // address field.
    if ( (pdata[1] & 0x03) == 0x03 )
        len_80211 += packet->l2_addr_len;

    // Look for the QoS indicator bit.
    if ( (fc_80211 >> 4) & 0x08 )
    {
        // Skip in case of A-MSDU subframes indicated by QoS
        // control field.
        if ( pdata[len_80211] & 0x80)
            return;

        len_80211 += 2;
    }

    if ( pdata + len_80211 >= end_of_data )
    {
        packet->Weird("truncated_802_11_header");
        return;
    }

    // Determine link-layer addresses based
    // on 'To DS' and 'From DS' flags
    switch ( pdata[1] & 0x03 ) {
        case 0x00:
            packet->l2_src = pdata + 10;
            packet->l2_dst = pdata + 4;
            break;

        case 0x01:
            packet->l2_src = pdata + 10;
            packet->l2_dst = pdata + 16;
            break;

        case 0x02:
            packet->l2_src = pdata + 16;
            packet->l2_dst = pdata + 4;
            break;

        case 0x03:
            packet->l2_src = pdata + 24;
            packet->l2_dst = pdata + 16;
            break;
    }

    // skip 802.11 data header
    pdata += len_80211;

    if ( pdata + 8 >= end_of_data )
    {
        packet->Weird("truncated_802_11_header");
        return;
    }
    // Check that the DSAP and SSAP are both SNAP and that the control
    // field indicates that this is an unnumbered frame.
    // The organization code (24bits) needs to also be zero to
    // indicate that this is encapsulated ethernet.
    if ( pdata[0] == 0xAA && pdata[1] == 0xAA && pdata[2] == 0x03 &&
         pdata[3] == 0 && pdata[4] == 0 && pdata[5] == 0 )
    {
        pdata += 6;
    }
    else
    {
        // If this is a logical link control frame without the
        // possibility of having a protocol we care about, we'll
        // just skip it for now.
        return;
    }

    protocol = (pdata[0] << 8) + pdata[1];
    if ( protocol == 0x0800 )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == 0x86DD )
        packet->l3_proto = L3_IPV6;
    else if ( protocol == 0x0806 || protocol == 0x8035 )
        packet->l3_proto = L3_ARP;
    else
    {
        packet->Weird("non_ip_packet_in_ieee802_11");
        return;
    }
    pdata += 2;

    // END of IEEE802.11

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
