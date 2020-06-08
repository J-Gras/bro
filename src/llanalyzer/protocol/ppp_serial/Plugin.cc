#include "PPPSerial.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_PPPSerial {

class Plugin : public ::plugin::Plugin {
public:
    ::plugin::Configuration Configure()
		{
        AddComponent(new zeek::llanalyzer::Component("PPPSerialAnalyzer",
		             zeek::llanalyzer::PPPSerial::PPPSerialAnalyzer::Instantiate));

        ::plugin::Configuration config;
        config.name = "LLPOC::PPPSerialAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
		}

} plugin;

}
