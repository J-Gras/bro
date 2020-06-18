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

	packet->eth_type = protocol;
	packet->l2_dst = pdata;
	packet->l2_src = pdata + 6;

	pdata += 14;

	bool saw_vlan = false;

	while ( protocol == 0x8100 || protocol == 0x9100 )
		{
		switch ( protocol )
			{
			// VLAN carried over the ethernet frame.
			// 802.1q / 802.1ad
			case 0x8100:
			case 0x9100:
				{
				if ( pdata + 4 >= end_of_data )
					{
					packet->Weird("truncated_link_header");
					return std::make_tuple(AnalyzerResult::Failed, 0);
					}

				auto& vlan_ref = saw_vlan ? packet->inner_vlan : packet->vlan;
				vlan_ref = ((pdata[0] << 8u) + pdata[1]) & 0xfff;
				protocol = ((pdata[2] << 8u) + pdata[3]);
				pdata += 4; // Skip the vlan header
				saw_vlan = true;
				packet->eth_type = protocol;
				break;
				}
			}
		}

	return std::make_tuple(AnalyzerResult::Continue, protocol);
	}
