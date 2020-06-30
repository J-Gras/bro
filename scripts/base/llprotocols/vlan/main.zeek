module LL_VLAN;

redef LLAnalyzer::config_map += {
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8847, $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8100, $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8864, $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER)
};
