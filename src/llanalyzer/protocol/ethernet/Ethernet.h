#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace Ethernet {

class EthernetAnalyzer : public Analyzer {
public:
    EthernetAnalyzer();
    ~EthernetAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new EthernetAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
