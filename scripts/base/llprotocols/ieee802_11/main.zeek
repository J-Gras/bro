module LL_IEEE802_11;

const DLT_IEEE802_11 : count = 105;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_IEEE802_11,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x0800,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x86DD,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};
