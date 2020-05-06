
#include "PPPSerial.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_PPPSerial {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("PPPSerialAnalyzer",
                     llanalyzer::PPPSerial::PPPSerialAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::PPPSerialAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}