#include "IEEE802_11_Radio.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_IEEE802_11_Radio {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IEEE802_11_RadioAnalyzer",
		                 zeek::llanalyzer::IEEE802_11_Radio::IEEE802_11_RadioAnalyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::IEEE802_11_RadioAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;
}
