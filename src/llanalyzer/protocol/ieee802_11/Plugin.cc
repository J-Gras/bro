#include "IEEE802_11.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_IEEE802_11 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IEEE802_11Analyzer",
		                 zeek::llanalyzer::IEEE802_11::IEEE802_11Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::IEEE802_11Analyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
