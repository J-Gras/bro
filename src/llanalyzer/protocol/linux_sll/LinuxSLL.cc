#include "LinuxSLL.h"

using namespace zeek::llanalyzer::LinuxSLL;

LinuxSLLAnalyzer::LinuxSLLAnalyzer()
	: zeek::llanalyzer::Analyzer("LinuxSLL")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> LinuxSLLAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + sizeof(SLLHeader) >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_Linux_SLL_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto hdr = (const SLLHeader*)pdata;
	//TODO: Handle different ARPHRD_types
	identifier_t protocol = ntohs(hdr->protocol_type);
	packet->l2_src = (u_char*) &(hdr->addr);

	pdata += sizeof(SLLHeader);
	return { AnalyzerResult::Continue, protocol };
	}
