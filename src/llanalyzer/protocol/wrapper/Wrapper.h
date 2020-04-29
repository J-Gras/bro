#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Wrapper {

class WrapperAnalyzer : public Analyzer {
public:
    WrapperAnalyzer();
    ~WrapperAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new WrapperAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
