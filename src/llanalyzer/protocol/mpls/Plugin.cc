#include "MPLS.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_MPLS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("MPLSAnalyzer",
		                 zeek::llanalyzer::MPLS::MPLSAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::MPLSAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
