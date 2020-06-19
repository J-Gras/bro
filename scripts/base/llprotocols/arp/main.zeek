module LL_ARP;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLANANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

# RARP
redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};
