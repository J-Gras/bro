module LL_PPPOE;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8864,
                                                         $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER,
                                                         $identifier=0x8864,
                                                         $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER)};
