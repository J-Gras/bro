#include "Wrapper.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("WrapperAnalyzer",
		                 zeek::llanalyzer::Wrapper::WrapperAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::WrapperAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
