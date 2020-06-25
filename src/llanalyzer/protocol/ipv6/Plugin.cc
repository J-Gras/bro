#include "plugin/Plugin.h"
#include "IPv6.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_IPv6 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IPv6Analyzer",
		             zeek::llanalyzer::IPv6::IPv6Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::IPv6Analyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}
} plugin;

}
