#include "Ethernet.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::Ethernet;

EthernetAnalyzer::EthernetAnalyzer()
	: zeek::llanalyzer::Analyzer("EthernetAnalyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> EthernetAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( pdata[12] == 0x89 && pdata[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( pdata + cfplen + 14 >= end_of_data )
			{
			packet->Weird("truncated_link_header_cfp");
			return std::make_tuple(AnalyzerResult::Failed, 0);
			}

		pdata += cfplen;
		}

	// Get protocol being carried from the ethernet frame.
	identifier_t protocol = (pdata[12] << 8) + pdata[13];

	// Skip everything but Ethernet II packets
	if ( protocol < 1536 )
		return std::make_tuple(AnalyzerResult::Terminate, protocol);

	packet->eth_type = protocol;
	packet->l2_dst = pdata;
	packet->l2_src = pdata + 6;

	pdata += 14;

	return std::make_tuple(AnalyzerResult::Continue, protocol);
	}
