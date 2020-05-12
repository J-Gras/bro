#include "PPPSerial.h"
#include "NetVar.h"

using namespace llanalyzer::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer() : llanalyzer::Analyzer("PPPSerialAnalyzer") { }

PPPSerialAnalyzer::~PPPSerialAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> PPPSerialAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;

    // Extract protocol identifier
    identifier_t protocol = (pdata[2] << 8) + pdata[3];
    pdata += 4; // skip link header

    return std::make_tuple(AnalyzerResult::Continue, protocol);
}
