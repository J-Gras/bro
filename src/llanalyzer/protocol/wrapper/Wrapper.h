#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Wrapper {

class WrapperAnalyzer : public Analyzer {
public:
    WrapperAnalyzer();
    ~WrapperAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new WrapperAnalyzer();
    }
};

} }
