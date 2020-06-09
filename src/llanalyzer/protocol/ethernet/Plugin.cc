#include "Ethernet.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_Ethernet {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("EthernetAnalyzer",
		                 zeek::llanalyzer::Ethernet::EthernetAnalyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::EthernetAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
