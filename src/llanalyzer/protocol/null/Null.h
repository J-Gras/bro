#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Null {

class NullAnalyzer : public Analyzer {
public:
    NullAnalyzer();
    ~NullAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new NullAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
