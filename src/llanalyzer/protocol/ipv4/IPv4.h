#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IPv4 {

class IPv4Analyzer : public Analyzer {
public:
    IPv4Analyzer();
    ~IPv4Analyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IPv4Analyzer();
    }
};

} }
