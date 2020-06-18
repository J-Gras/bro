#include "VLAN.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_VLAN {

class Plugin : public ::plugin::Plugin {
public:
    ::plugin::Configuration Configure()
        {
        AddComponent(new zeek::llanalyzer::Component("VLANAnalyzer",
                         zeek::llanalyzer::VLAN::VLANAnalyzer::Instantiate));

        ::plugin::Configuration config;
        config.name = "LLPOC::VLANAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
        }

} plugin;

}
