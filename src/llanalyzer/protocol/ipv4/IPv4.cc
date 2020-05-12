#include "IPv4.h"

using namespace llanalyzer::IPv4;

IPv4Analyzer::IPv4Analyzer() : llanalyzer::Analyzer("IPv4Analyzer") { }

IPv4Analyzer::~IPv4Analyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> IPv4Analyzer::analyze(Packet* packet) {
    packet->l3_proto = L3_IPV4;
    packet->hdr_size = (packet->cur_pos - packet->data);

    // Leave LL analyzer land
    return std::make_tuple(AnalyzerResult::Terminate, 0);
}
