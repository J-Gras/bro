
#include "Ethernet.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_Ethernet {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("EthernetAnalyzer",
                     llanalyzer::Ethernet::EthernetAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::EthernetAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}