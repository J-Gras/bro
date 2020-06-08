#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace FDDI {

class FDDIAnalyzer : public Analyzer {
public:
    FDDIAnalyzer();
    ~FDDIAnalyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new FDDIAnalyzer();
    }
};

} }
