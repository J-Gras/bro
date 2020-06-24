#include "plugin/Plugin.h"
#include "LinuxSLL.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_LinuxSLL {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("LinuxSLLAnalyzer",
		                 zeek::llanalyzer::LinuxSLL::LinuxSLLAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLPOC::LinuxSLLAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
