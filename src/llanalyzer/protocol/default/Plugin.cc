
#include "Default.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_Default {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("DefaultAnalyzer",
                     llanalyzer::Default::DefaultAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::DefaultAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}