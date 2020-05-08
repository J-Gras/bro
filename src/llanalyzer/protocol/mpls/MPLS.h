#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace MPLS {

class MPLSAnalyzer : public Analyzer {
public:
    MPLSAnalyzer();
    ~MPLSAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new MPLSAnalyzer();
    }
};

} }
