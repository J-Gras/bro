#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace IEEE802_11 {

class IEEE802_11Analyzer : public Analyzer {
public:
    IEEE802_11Analyzer();
    ~IEEE802_11Analyzer() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new IEEE802_11Analyzer();
    }

private:
    uint16_t protocol;
    Packet* currentPacket;
};

} }
