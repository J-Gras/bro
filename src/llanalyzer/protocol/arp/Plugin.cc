
#include "ARP.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_ARP {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("ARPAnalyzer",
                     llanalyzer::ARP::ARPAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::ARPAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}