#include "VLAN.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_VLAN {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure()
        {
        AddComponent(new zeek::llanalyzer::Component("VLANAnalyzer",
                         zeek::llanalyzer::VLAN::VLANAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "LLAnalyzer::VLANAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
        }

} plugin;

}
