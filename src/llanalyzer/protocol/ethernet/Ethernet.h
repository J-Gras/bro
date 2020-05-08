#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Ethernet {

class EthernetAnalyzer : public Analyzer {
public:
    EthernetAnalyzer();
    ~EthernetAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new EthernetAnalyzer();
    }
};

} }
