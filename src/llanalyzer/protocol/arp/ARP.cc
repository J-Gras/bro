#include "ARP.h"

using namespace zeek::llanalyzer::ARP;

ARPAnalyzer::ARPAnalyzer()
	: zeek::llanalyzer::Analyzer("ARP")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> ARPAnalyzer::Analyze(Packet* packet)
	{
	// TODO: Make ARP analyzer a native LL analyzer
	packet->l3_proto = L3_ARP;
	packet->hdr_size = (packet->cur_pos - packet->data);

	// Leave LL analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
