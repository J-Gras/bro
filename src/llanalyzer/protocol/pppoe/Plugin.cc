#include "PPPoE.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_PPPoE {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure()
        {
        AddComponent(new zeek::llanalyzer::Component("PPPoEAnalyzer",
                         zeek::llanalyzer::PPPoE::PPPoEAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "LLPOC::PPPoEAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
        }

} plugin;

}
