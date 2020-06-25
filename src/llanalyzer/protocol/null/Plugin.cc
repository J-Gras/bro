#include "plugin/Plugin.h"
#include "Null.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_Null {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("NullAnalyzer",
		                 zeek::llanalyzer::Null::NullAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::NullAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
