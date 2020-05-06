#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace NFLog {

class NFLogAnalyzer : public Analyzer {
public:
    NFLogAnalyzer();
    ~NFLogAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new NFLogAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
