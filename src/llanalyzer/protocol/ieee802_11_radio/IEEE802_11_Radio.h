#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IEEE802_11_Radio {

class IEEE802_11_RadioAnalyzer : public Analyzer {
public:
    IEEE802_11_RadioAnalyzer();
    ~IEEE802_11_RadioAnalyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IEEE802_11_RadioAnalyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
