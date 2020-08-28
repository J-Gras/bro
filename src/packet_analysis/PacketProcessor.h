#pragma once

#include <iosource/Packet.h>

namespace zeek::packet_analysis {

/**
 * This is the base class for a class that processes packets beyond the
 * processing that happens in packet_analysis. This is currently only
 * implemented by the NetSessions code.
 */
class PacketProcessor {
public:

	virtual ~PacketProcessor() = default;
	virtual void NextPacket(double t, const Packet* pkt) = 0;
};

} // namespace zeek::packet_analysis
