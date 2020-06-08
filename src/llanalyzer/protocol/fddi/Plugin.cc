
#include "FDDI.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace plugin {
namespace LLPOC_FDDI {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() {
        AddComponent(new ::llanalyzer::Component("FDDIAnalyzer",
                     llanalyzer::FDDI::FDDIAnalyzer::Instantiate));

        plugin::Configuration config;
        config.name = "LLPOC::FDDIAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
    }
} plugin;

}
}