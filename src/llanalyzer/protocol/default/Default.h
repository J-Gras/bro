#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Default {

class DefaultAnalyzer : public Analyzer {
public:
    DefaultAnalyzer();
    ~DefaultAnalyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new DefaultAnalyzer();
    }
};

} }
