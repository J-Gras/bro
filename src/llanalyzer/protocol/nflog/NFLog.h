#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace NFLog {

class NFLogAnalyzer : public Analyzer {
public:
    NFLogAnalyzer();
    ~NFLogAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new NFLogAnalyzer();
    }
};

} }
