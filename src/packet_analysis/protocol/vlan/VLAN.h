// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::VLAN {

class VLANAnalyzer : public Analyzer {
public:
	VLANAnalyzer();
	~VLANAnalyzer() override = default;

	AnalyzerResult AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<VLANAnalyzer>();
		}
};

}
