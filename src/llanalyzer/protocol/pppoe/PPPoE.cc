#include "PPPoE.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer()
    : zeek::llanalyzer::Analyzer("PPPoEAnalyzer")
    {
    }

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> PPPoEAnalyzer::Analyze(Packet* packet)
    {
    auto& pdata = packet->cur_pos;

    if ( pdata + 8 >= packet->GetEndOfData() )
        {
        packet->Weird("truncated_pppoe_header");
        return std::make_tuple(AnalyzerResult::Failed, 0);
        }

    // Extract protocol identifier
    identifier_t protocol = (pdata[6] << 8u) + pdata[7];
    pdata += 8; // Skip the PPPoE session and PPP header

    return std::make_tuple(AnalyzerResult::Continue, protocol);
    }
