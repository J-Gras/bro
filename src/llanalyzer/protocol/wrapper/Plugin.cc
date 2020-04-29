
#include "Wrapper.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("WrapperAnalyzer",
                     llanalyzer::Wrapper::WrapperAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::WrapperAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}