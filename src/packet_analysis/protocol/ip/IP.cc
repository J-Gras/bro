// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "zeek/NetVar.h"
#include "zeek/IP.h"
#include "zeek/Discard.h"
#include "zeek/PacketFilter.h"
#include "zeek/Sessions.h"
#include "zeek/RunState.h"
#include "zeek/Frag.h"
#include "zeek/Event.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer()
	: zeek::packet_analysis::Analyzer("IP")
	{
	discarder = new detail::Discarder();
	if ( ! discarder->IsActive() )
		{
		delete discarder;
		discarder = nullptr;
		}
	}

IPAnalyzer::~IPAnalyzer()
	{
	}

bool IPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	EncapsulationStack* encapsulation = nullptr;
	auto it = packet->key_store.find("encap");
	if ( it != packet->key_store.end() )
		encapsulation = std::any_cast<EncapsulationStack*>(*it);

	// Assume we're pointing at IP. Just figure out which version.
	if ( sizeof(struct ip) >= len )
		{
		packet->Weird("packet_analyzer_truncated_header");
		return false;
		}

	// TODO: i feel like this could be generated as we move along the header hierarchy.
	packet->hdr_size = static_cast<int32_t>(data - packet->data);

	if ( packet->hdr_size > packet->cap_len )
		{
		packet->Weird("truncated_link_frame");
		return false;
		}

	auto ip = (const struct ip *)data;
	uint32_t protocol = ip->ip_v;
	uint32_t caplen = packet->cap_len - packet->hdr_size;

	std::unique_ptr<IP_Hdr> ip_hdr = nullptr;
	if ( protocol == 4 )
		{
		// TODO: double-check
		if ( sizeof(struct ip) >= caplen )
			{
			packet->Weird("truncated_IP");
			return false;
			}

		ip_hdr = std::make_unique<IP_Hdr>(ip, false);
		}
	else if ( protocol == 6 )
		{
		if ( caplen < sizeof(struct ip6_hdr) )
			{
			packet->Weird("truncated_IP");
			return false;
			}

		ip_hdr = std::make_unique<IP_Hdr>((const struct ip6_hdr*) data, false, caplen);
		}
	else
		{
		packet->Weird("unknown_ip_version");
		return false;
		}

	const struct ip* ip4 = ip_hdr->IP4_Hdr();

	// TODO: Shouldn't this be the same as the len value we have already? Should this just check
	// for whether they don't match and throw a weird for that?
	uint32_t total_len = ip_hdr->TotalLen();
	if ( total_len == 0 )
		{
		// TCP segmentation offloading can zero out the ip_len field.
		packet->Weird("ip_hdr_len_zero", encapsulation);

		// Cope with the zero'd out ip_len field by using the caplen.
		total_len = packet->cap_len - packet->hdr_size;
		}

	// TODO: this basically duplicates an earlier check, I think
	if ( packet->len < total_len + packet->hdr_size )
		{
		packet->Weird("truncated_IP", encapsulation);
		return false;
		}

	// For both of these it is safe to pass ip_hdr because the presence
	// is guaranteed for the functions that pass data to us.
	uint16_t ip_hdr_len = ip_hdr->HdrLen();
	if ( ip_hdr_len > len )
		{
		sessions->Weird("invalid_IP_header_size", ip_hdr.get(), encapsulation);
		return false;
		}

	if ( ip_hdr_len > caplen )
		{
		sessions->Weird("internally_truncated_header", ip_hdr.get(), encapsulation);
		return false;
		}

	if ( ip_hdr->IP4_Hdr() )
		{
		if ( ip_hdr_len < sizeof(struct ip) )
			{
			packet->Weird("IPv4_min_header_size");
			return false;
			}
		}
	else
		{
		if ( ip_hdr_len < sizeof(struct ip6_hdr) )
			{
			packet->Weird("IPv6_min_header_size");
			return false;
			}
		}

	// Ignore if packet matches packet filter.
	// TODO: set the right variable values below
	detail::PacketFilter* packet_filter = sessions->GetPacketFilter(false);
	if ( packet_filter && packet_filter->Match(ip_hdr.get(), len, caplen) )
		 return false;

	if ( ! packet->l2_checksummed && ! detail::ignore_checksums && ip4 &&
	     ones_complement_checksum((void*) ip4, ip_hdr_len, 0) != 0xffff )
		{
		sessions->Weird("bad_IP_checksum", packet, encapsulation);
		return false;
		}

	if ( discarder && discarder->NextPacket(ip_hdr.get(), len, caplen) )
		return false;

	detail::FragReassembler* f = nullptr;

	if ( ip_hdr->IsFragment() )
		{
		packet->dump_packet = true;	// always record fragments

		if ( caplen < len )
			{
			sessions->Weird("incompletely_captured_fragment", ip_hdr.get(), encapsulation);

			// Don't try to reassemble, that's doomed.
			// Discard all except the first fragment (which
			// is useful in analyzing header-only traces)
			if ( ip_hdr->FragOffset() != 0 )
				return false;
			}
		else
			{
			f = detail::fragment_mgr->NextFragment(run_state::processing_start_time, ip_hdr.get(), packet->data + packet->hdr_size);
			const IP_Hdr* ih = f->ReassembledPkt();
			if ( ! ih )
				// It didn't reassemble into anything yet.
				return false;

			ip4 = ih->IP4_Hdr();
			ip_hdr = std::unique_ptr<IP_Hdr>(ih->Copy());

			caplen = len = ip_hdr->TotalLen();
			ip_hdr_len = ip_hdr->HdrLen();

			if ( ip_hdr_len > len )
				{
				sessions->Weird("invalid_IP_header_size", ip_hdr.get(), encapsulation);
				return false;
				}
			}
		}

	detail::FragReassemblerTracker frt(f);

	// We stop building the chain when seeing IPPROTO_ESP so if it's
	// there, it's always the last.
	if ( ip_hdr->LastHeader() == IPPROTO_ESP )
		{
		packet->dump_packet = true;
		if ( esp_packet )
			event_mgr.Enqueue(esp_packet, ip_hdr->ToPktHdrVal());

		// Can't do more since upper-layer payloads are going to be encrypted.
		return true;
		}

#ifdef ENABLE_MOBILE_IPV6
	// We stop building the chain when seeing IPPROTO_MOBILITY so it's always
	// last if present.
	if ( ip_hdr->LastHeader() == IPPROTO_MOBILITY )
		{
		dump_this_packet = true;

		if ( ! ignore_checksums && mobility_header_checksum(ip_hdr) != 0xffff )
			{
			sessions->Weird("bad_MH_checksum", packet, encapsulation);
			return;
			}

		if ( mobile_ipv6_message )
			event_mgr.Enqueue(mobile_ipv6_message, ip_hdr->ToPktHdrVal());

		if ( ip_hdr->NextProto() != IPPROTO_NONE )
			sessions->Weird("mobility_piggyback", packet, encapsulation);

		return;
		}
#endif

	// TODO: Where does it go from here? Into run_state::dispatch_packet? Directly into Sessions::NextPacket?
	int proto = ip_hdr->NextProto();

	// Advance the data pointer past the IP header based on the header length
	data += ip_hdr_len;

	switch ( proto ) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		packet->hdr_size = static_cast<int32_t>(data - packet->data);
		sessions->DoNextPacket(run_state::processing_start_time, packet, ip_hdr.get(), encapsulation);
		break;
	case IPPROTO_GRE:
		// TODO: strip the header, pass to the GRE plugin, which will pass it back here again
		break;
	case IPPROTO_IPV4:
	case IPPROTO_IPV6:
		// TODO: strip the header, pass back into the IP plugin
		break;
	case IPPROTO_NONE:
		// If the packet is encapsulated in Teredo, then it was a bubble and
		// the Teredo analyzer may have raised an event for that, else we're
		// not sure the reason for the No Next header in the packet.
		// TODO
		// if ( ! ( encapsulation &&
		//      encapsulation->LastType() == BifEnum::Tunnel::TEREDO ) )
		// 	Weird("ipv6_no_next", packet);

		break;
	default:
		sessions->Weird("unknown_protocol", packet, encapsulation, util::fmt("%d", proto));
		return false;
	}

	if ( f )
		// Above we already recorded the fragment in its entirety.
		// TODO: re: above comment, where?
		f->DeleteTimer();

	return true;
	}
