#include "PPPSerial.h"
#include "NetVar.h"

using namespace llanalyzer::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer() : llanalyzer::Analyzer("PPPSerialAnalyzer") { }

PPPSerialAnalyzer::~PPPSerialAnalyzer() = default;

std::tuple<llanalyzer::AnalyzerResult, llanalyzer::identifier_t> PPPSerialAnalyzer::analyze(Packet* packet) {
    auto& pdata = packet->cur_pos;
    auto end_of_data = packet->GetEndOfData();

    pdata += Packet::GetLinkHeaderSize(packet->link_type);

    // Extract protocol identifier
    identifier_t protocol = (pdata[2] << 8) + pdata[3];

    if ( protocol == 0x0281 )
    {
        return std::make_tuple(AnalyzerResult::Continue, protocol);
    }
    else if ( protocol == 0x0021 )
        packet->l3_proto = L3_IPV4;
    else if ( protocol == 0x0057 )
        packet->l3_proto = L3_IPV6;
    else
        {
        // Neither IPv4 nor IPv6.
        packet->Weird("non_ip_packet_in_ppp_encapsulation");
        return std::make_tuple(AnalyzerResult::Failed, 0);
        }

    // Calculate how much header we've used up.
    packet->hdr_size = (pdata - packet->data);
    return std::make_tuple(AnalyzerResult::Failed, 0);
}
