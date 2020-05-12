#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IEEE802_11_Radio {

class IEEE802_11_RadioAnalyzer : public Analyzer {
public:
    IEEE802_11_RadioAnalyzer();
    ~IEEE802_11_RadioAnalyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IEEE802_11_RadioAnalyzer();
    }
};

} }
