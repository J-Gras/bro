#include "Null.h"
#include "NetVar.h"

using namespace llanalyzer::Null;

NullAnalyzer::NullAnalyzer() : llanalyzer::Analyzer("NullAnalyzer"), protocol(0), currentPacket(nullptr) {
}

NullAnalyzer::~NullAnalyzer() = default;

uint32_t NullAnalyzer::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    protocol = (packet->cur_pos[3] << 24) + (packet->cur_pos[2] << 16) +
            (packet->cur_pos[1] << 8) + packet->cur_pos[0];
    return protocol;
}

void NullAnalyzer::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }
    const u_char *pdata = packet->data;
    const u_char *end_of_data = packet->data + packet->cap_len;

    int protocol = (pdata[3] << 24) + (pdata[2] << 16) + (pdata[1] << 8) + pdata[0];
    pdata += Packet::GetLinkHeaderSize(packet->link_type);

    // From the Wireshark Wiki: "AF_INET6, unfortunately, has
    // different values in {NetBSD,OpenBSD,BSD/OS},
    // {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
    // packet might have a link-layer header with 24, 28, or 30
    // as the AF_ value." As we may be reading traces captured on
    // platforms other than what we're running on, we accept them
    // all here.

    if ( protocol == AF_INET )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == 24 || protocol == 28 || protocol == 30 )
        packet->l3_proto = L3_IPV6;
    else
    {
        packet->Weird("non_ip_packet_in_null_transport");
        return;
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

