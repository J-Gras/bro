#include "MPLS.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_MPLS {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("MPLSAnalyzer",
		                 zeek::llanalyzer::MPLS::MPLSAnalyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::MPLSAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
