#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Null {

class NullAnalyzer : public Analyzer {
public:
    NullAnalyzer();
    ~NullAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new NullAnalyzer();
    }
};

} }
