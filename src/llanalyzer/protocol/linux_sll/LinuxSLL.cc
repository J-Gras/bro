#include "LinuxSLL.h"

using namespace zeek::llanalyzer::LinuxSLL;

LinuxSLLAnalyzer::LinuxSLLAnalyzer()
	: zeek::llanalyzer::Analyzer("LinuxSLLAnalyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> LinuxSLLAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// See https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html

	if ( pdata + 16 >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_Linux_SLL_header");
		return std::make_tuple(AnalyzerResult::Failed, 0);
		}

	auto hdr = (const SLLHeader*)pdata;
	//TODO: Handle different ARPHRD_types
	identifier_t protocol = ntohs(hdr->protocol_type);

	pdata += 16;
	return std::make_tuple(AnalyzerResult::Continue, protocol);
	}
