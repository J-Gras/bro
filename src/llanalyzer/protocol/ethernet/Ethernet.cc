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

	while ( protocol == 0x8100 || protocol == 0x9100 ||
	        protocol == 0x8864 )
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

			// PPPoE carried over the ethernet frame.
			case 0x8864:
				{
				if ( pdata + 8 >= end_of_data )
					{
					packet->Weird("truncated_link_header");
					return std::make_tuple(AnalyzerResult::Failed, 0);
					}

				protocol = (pdata[6] << 8u) + pdata[7];
				pdata += 8; // Skip the PPPoE session and PPP header

				if ( protocol == 0x0021 )
					packet->l3_proto = L3_IPV4;
				else if ( protocol == 0x0057 )
					packet->l3_proto = L3_IPV6;
				else
					{
					// Neither IPv4 nor IPv6.
					packet->Weird("non_ip_packet_in_pppoe_encapsulation");
					return std::make_tuple(AnalyzerResult::Failed, 0);
					}
				break;
				}
			}
		}

	// Check for MPLS in VLAN.
	if ( protocol == 0x8847 )
		return std::make_tuple(AnalyzerResult::Continue, protocol);

	// Normal path to determine Layer 3 protocol.
	if ( packet->l3_proto == L3_UNKNOWN )
		{
		if ( protocol == 0x800 )
			packet->l3_proto = L3_IPV4;
		else if ( protocol == 0x86dd )
			packet->l3_proto = L3_IPV6;
		else if ( protocol == 0x0806 || protocol == 0x8035 )
			packet->l3_proto = L3_ARP;
		else
			{
			// Neither IPv4 nor IPv6.
			packet->Weird("non_ip_packet_in_ethernet");
			return std::make_tuple(AnalyzerResult::Failed, 0);
			}
		}

	// TODO: investigate how hdr_size is used
	// Calculate how much header we've used up.
	packet->hdr_size = (pdata - packet->data);

	return std::make_tuple(AnalyzerResult::Terminate, 0);
	}
