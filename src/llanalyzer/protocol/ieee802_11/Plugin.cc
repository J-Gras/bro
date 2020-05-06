
#include "IEEE802_11.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_IEEE802_11 {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("IEEE802_11Analyzer",
                     llanalyzer::IEEE802_11::IEEE802_11Analyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::IEEE802_11Analyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}