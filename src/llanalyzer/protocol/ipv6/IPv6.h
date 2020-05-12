#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IPv6 {

class IPv6Analyzer : public Analyzer {
public:
    IPv6Analyzer();
    ~IPv6Analyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IPv6Analyzer();
    }
};

} }
