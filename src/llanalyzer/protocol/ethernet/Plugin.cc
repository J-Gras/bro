#include "Ethernet.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_Ethernet {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("EthernetAnalyzer",
		                 zeek::llanalyzer::Ethernet::EthernetAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::EthernetAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
