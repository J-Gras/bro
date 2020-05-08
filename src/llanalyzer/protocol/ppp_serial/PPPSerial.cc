#include "PPPSerial.h"
#include "NetVar.h"

using namespace llanalyzer::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer() : llanalyzer::Analyzer("PPPSerialAnalyzer"), protocol(0), currentPacket(nullptr) {
}

PPPSerialAnalyzer::~PPPSerialAnalyzer() = default;

uint32_t PPPSerialAnalyzer::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    protocol = (packet->cur_pos[2] << 8) + packet->cur_pos[3];
    return protocol;
}

void PPPSerialAnalyzer::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    // Unfortunately some packets on the link might have MPLS labels
    // while others don't. That means we need to ask the link-layer if
    // labels are in place.
    bool have_mpls = false;

    auto pdata = packet->cur_pos;
    auto end_of_data = packet->GetEndOfData();

    pdata += Packet::GetLinkHeaderSize(packet->link_type);

    if ( protocol == 0x0281 )
    {
        // MPLS Unicast. Remove the pdata link layer and
        // denote a header size of zero before the IP header.
        have_mpls = true;
    }
    else if ( protocol == 0x0021 )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == 0x0057 )
        packet->l3_proto = L3_IPV6;
    else
        {
        // Neither IPv4 nor IPv6.
        packet->Weird("non_ip_packet_in_ppp_encapsulation");
        return;
        }

    if (have_mpls) {
        // Skip the MPLS label stack.
        bool end_of_stack = false;

        while (!end_of_stack) {
            if (pdata + 4 >= end_of_data) {
                packet->Weird("truncated_link_header");
                return;
            }

            end_of_stack = *(pdata + 2u) & 0x01;
            pdata += 4;
        }

        // We assume that what remains is IP
        if (pdata + sizeof(struct ip) >= end_of_data) {
            packet->Weird("no_ip_in_mpls_payload");
            return;
        }

        const struct ip *ip = (const struct ip *) pdata;

        if (ip->ip_v == 4)
            packet->l3_proto = L3_IPV4;
        else if (ip->ip_v == 6)
            packet->l3_proto = L3_IPV6;
        else {
            // Neither IPv4 nor IPv6.
            packet->Weird("no_ip_in_mpls_payload");
            return;
        }
    } else if (encap_hdr_size) {
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
