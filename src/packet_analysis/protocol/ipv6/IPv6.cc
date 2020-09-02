// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv6.h"
#include "Sessions.h"
#include "RunState.h"

using namespace zeek::packet_analysis::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::packet_analysis::Analyzer("IPv6")
	{
	}

bool IPv6Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	packet->l3_proto = L3_IPV6;
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);
	packet->session_analysis = true;

	// Calculate header size after processing packet layers.
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);

	// Pass on to the session analyzers.
	run_state::detail::dispatch_packet(packet, sessions);

	// Leave packet analyzer land
	return true;
	}
