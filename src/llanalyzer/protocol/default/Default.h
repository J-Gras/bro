#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::Default {

class DefaultAnalyzer : public Analyzer {
public:
    DefaultAnalyzer();
    ~DefaultAnalyzer() override = default;

    std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

    static Analyzer* Instantiate()
		{
        return new DefaultAnalyzer();
		}
};

}
