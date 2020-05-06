#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace PPPSerial {

class PPPSerialAnalyzer : public Analyzer {
public:
    PPPSerialAnalyzer();
    ~PPPSerialAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new PPPSerialAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
