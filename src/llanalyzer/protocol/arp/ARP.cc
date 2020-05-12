#include "ARP.h"

using namespace llanalyzer::ARP;

ARPAnalyzer::ARPAnalyzer() : llanalyzer::Analyzer("ARPAnalyzer") { }

ARPAnalyzer::~ARPAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> ARPAnalyzer::analyze(Packet* packet) {
    // TODO: Make ARP analyzer a native LL analyzer
    packet->l3_proto = L3_ARP;
    packet->hdr_size = (packet->cur_pos - packet->data);

    // Leave LL analyzer land
    return std::make_tuple(AnalyzerResult::Terminate, 0);
}
