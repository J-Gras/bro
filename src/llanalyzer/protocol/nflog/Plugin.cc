#include "NFLog.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_NFLog {

class Plugin : public ::plugin::Plugin {
public:
    ::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("NFLogAnalyzer",
                     llanalyzer::NFLog::NFLogAnalyzer::Instantiate));

        ::plugin::Configuration config;
        config.name = "LLPOC::NFLogAnalyzer";
        config.description = "A wrapper for the original zeek code.";
        return config;
		}
} plugin;

}
