#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace PPPSerial {

class PPPSerialAnalyzer : public Analyzer {
public:
    PPPSerialAnalyzer();
    ~PPPSerialAnalyzer() override;

    identifier_t analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new PPPSerialAnalyzer();
    }
};

} }
