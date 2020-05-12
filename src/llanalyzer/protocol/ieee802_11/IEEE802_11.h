#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IEEE802_11 {

class IEEE802_11Analyzer : public Analyzer {
public:
    IEEE802_11Analyzer();
    ~IEEE802_11Analyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IEEE802_11Analyzer();
    }
};

} }
