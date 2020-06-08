#include "FDDI.h"
#include "NetVar.h"

using namespace llanalyzer::FDDI;

FDDIAnalyzer::FDDIAnalyzer() : llanalyzer::Analyzer("FDDIAnalyzer") { }

FDDIAnalyzer::~FDDIAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> FDDIAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;
    auto hdr_size = 13 + 8; // FDDI header + LLC

    if ( pdata + hdr_size >= packet->GetEndOfData() )
    {
        packet->Weird("FDDI_analyzer_failed");
        return std::make_tuple(AnalyzerResult::Failed, 0);
    }

    // We just skip the header and hope for default analysis
    pdata += hdr_size;
    return std::make_tuple(AnalyzerResult::Continue, -1);
}

