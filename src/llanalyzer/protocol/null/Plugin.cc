#include "plugin/Plugin.h"
#include "Null.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_Null {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("NullAnalyzer",
		                 zeek::llanalyzer::Null::NullAnalyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::NullAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
