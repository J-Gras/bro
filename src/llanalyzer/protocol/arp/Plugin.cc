#include "plugin/Plugin.h"
#include "ARP.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_ARP {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("ARPAnalyzer",
		             zeek::llanalyzer::ARP::ARPAnalyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::ARPAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
