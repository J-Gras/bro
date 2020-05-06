
#include "Null.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_Null {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("NullAnalyzer",
                     llanalyzer::Null::NullAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::NullAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}