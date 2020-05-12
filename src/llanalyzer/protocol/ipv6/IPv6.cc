#include "IPv6.h"

using namespace llanalyzer::IPv6;

IPv6Analyzer::IPv6Analyzer() : llanalyzer::Analyzer("IPv6Analyzer") { }

IPv6Analyzer::~IPv6Analyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> IPv6Analyzer::analyze(Packet* packet) {
    packet->l3_proto = L3_IPV6;
    packet->hdr_size = (packet->cur_pos - packet->data);

    // Leave LL analyzer land
    return std::make_tuple(AnalyzerResult::Terminate, 0);
}
