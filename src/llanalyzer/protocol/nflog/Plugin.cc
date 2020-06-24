#include "NFLog.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_NFLog {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("NFLogAnalyzer",
		                 zeek::llanalyzer::NFLog::NFLogAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::NFLogAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}
} plugin;

}
