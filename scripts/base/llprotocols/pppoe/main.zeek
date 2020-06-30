module LL_PPPOE;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPOEANALYZER, $identifier=0x0021, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPOEANALYZER, $identifier=0x0057, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)
};
