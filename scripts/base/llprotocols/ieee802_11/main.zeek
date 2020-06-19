module LL_IEEE802_11;

const DLT_IEEE802_11 : count = 105;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_IEEE802_11,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11_RADIOANALYZER,
                                                         $identifier=DLT_IEEE802_11,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER)};
