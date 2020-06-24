#include "IPv4.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_IPv4 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IPv4Analyzer",
		                 zeek::llanalyzer::IPv4::IPv4Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::IPv4Analyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
