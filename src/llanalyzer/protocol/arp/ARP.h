#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace ARP {

class ARPAnalyzer : public Analyzer {
public:
    ARPAnalyzer();
    ~ARPAnalyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new ARPAnalyzer();
    }
};

} }
