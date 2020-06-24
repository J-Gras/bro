#include "Default.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_Default {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("DefaultAnalyzer",
		                 zeek::llanalyzer::Default::DefaultAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::DefaultAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
