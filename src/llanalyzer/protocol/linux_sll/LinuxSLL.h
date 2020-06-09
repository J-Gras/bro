#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::LinuxSLL {

class LinuxSLLAnalyzer : public Analyzer {
public:
	LinuxSLLAnalyzer();
	~LinuxSLLAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new LinuxSLLAnalyzer();
		}

private:
	struct SLLHeader
		{
		uint16_t packet_type;
		uint16_t arphrd_type;
		uint16_t addr_len;
		uint16_t protocol_type;
		uint64_t addr;
		} __attribute__((__packed__));
};

}
