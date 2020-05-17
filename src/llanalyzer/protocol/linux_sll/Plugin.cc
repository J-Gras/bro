
#include "LinuxSLL.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_LinuxSLL {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("LinuxSLLAnalyzer",
                     llanalyzer::LinuxSLL::LinuxSLLAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::LinuxSLLAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}