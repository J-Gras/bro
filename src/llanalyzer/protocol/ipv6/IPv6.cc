#include "IPv6.h"

using namespace zeek::llanalyzer::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::llanalyzer::Analyzer("IPv6Analyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> IPv6Analyzer::Analyze(Packet* packet)
	{
	packet->l3_proto = L3_IPV6;
	packet->hdr_size = (packet->cur_pos - packet->data);

	// Leave LL analyzer land
	return std::make_tuple(AnalyzerResult::Terminate, 0);
	}
