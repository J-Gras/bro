#include "Null.h"
#include "NetVar.h"

using namespace llanalyzer::Null;

NullAnalyzer::NullAnalyzer() : llanalyzer::Analyzer("NullAnalyzer") { }

NullAnalyzer::~NullAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> NullAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;

    if ( pdata + 4 >= packet->GetEndOfData() )
    {
        packet->Weird("null_analyzer_failed");
        return std::make_tuple(AnalyzerResult::Failed, 0);
    }

    identifier_t protocol = (pdata[3] << 24) + (pdata[2] << 16) + (pdata[1] << 8) + pdata[0];
    pdata += 4; // skip link header

    return std::make_tuple(AnalyzerResult::Continue, protocol);
}

