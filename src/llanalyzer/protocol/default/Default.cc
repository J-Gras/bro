#include "Default.h"
#include "NetVar.h"

using namespace llanalyzer::Default;

DefaultAnalyzer::DefaultAnalyzer() : llanalyzer::Analyzer("DefaultAnalyzer") { }

DefaultAnalyzer::~DefaultAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> DefaultAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;

    // Assume we're pointing at IP. Just figure out which version.
    if ( pdata + sizeof(struct ip) >= packet->GetEndOfData() )
    {
        packet->Weird("default_ll_analyser_failed");
        return std::make_tuple(AnalyzerResult::Failed, 0);
    }

    auto ip = (const struct ip *)pdata;
    identifier_t protocol = ip->ip_v;

    return std::make_tuple(AnalyzerResult::Continue, protocol);
}

