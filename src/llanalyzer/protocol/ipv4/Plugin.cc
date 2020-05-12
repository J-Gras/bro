
#include "IPv4.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_IPv4 {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("IPv4Analyzer",
                     llanalyzer::IPv4::IPv4Analyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::IPv4Analyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}