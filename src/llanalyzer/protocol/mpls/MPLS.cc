#include "MPLS.h"

using namespace llanalyzer::MPLS;

MPLSAnalyzer::MPLSAnalyzer() : llanalyzer::Analyzer("MPLSAnalyzer") { }

MPLSAnalyzer::~MPLSAnalyzer() = default;

llanalyzer::identifier_t MPLSAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;
    auto end_of_data = packet->GetEndOfData();

    // Skip the MPLS label stack.
    bool end_of_stack = false;

    while (!end_of_stack) {
        if (pdata + 4 >= end_of_data) {
            packet->Weird("truncated_link_header");
            return NO_NEXT_LAYER;
        }

        end_of_stack = *(pdata + 2u) & 0x01;
        pdata += 4;
    }

    // We assume that what remains is IP
    if (pdata + sizeof(struct ip) >= end_of_data) {
        packet->Weird("no_ip_in_mpls_payload");
        return NO_NEXT_LAYER;
    }

    auto ip = (const struct ip *) pdata;

    if (ip->ip_v == 4)
        packet->l3_proto = L3_IPV4;
    else if (ip->ip_v == 6)
        packet->l3_proto = L3_IPV6;
    else {
        // Neither IPv4 nor IPv6.
        packet->Weird("no_ip_in_mpls_payload");
        return NO_NEXT_LAYER;
    }

    packet->hdr_size = (pdata - packet->data);
    return NO_NEXT_LAYER;
}
