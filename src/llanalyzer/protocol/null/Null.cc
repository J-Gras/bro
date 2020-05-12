#include "Null.h"
#include "NetVar.h"

using namespace llanalyzer::Null;

NullAnalyzer::NullAnalyzer() : llanalyzer::Analyzer("NullAnalyzer") { }

NullAnalyzer::~NullAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> NullAnalyzer::analyze(Packet* packet) {
    auto pdata = packet->cur_pos;
    auto end_of_data = packet->GetEndOfData();

    identifier_t protocol = (pdata[3] << 24) + (pdata[2] << 16) + (pdata[1] << 8) + pdata[0];
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
        return std::make_tuple(AnalyzerResult::Failed, 0);
    }

    // Calculate how much header we've used up.
    packet->hdr_size = (pdata - packet->data);

    return std::make_tuple(AnalyzerResult::Continue, protocol);
}

