module LL_MPLS;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8847,
                                                         $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER,
                                                         $identifier=0x8847,
                                                         $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER,
                                                         $identifier=0x0281,
                                                         $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER)};
