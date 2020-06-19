module LL_VLAN;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8100,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x88A8,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x9100,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER,
                                                         $identifier=0x8100,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};
