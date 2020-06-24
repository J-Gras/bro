module LL_ETHERNET;

const DLT_EN10MB : count = 1;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_EN10MB,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ETHERNETANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8847,
                                                         $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x0800,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x86DD,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8100,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x88A8,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x9100,
                                                         $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER,
                                                         $identifier=0x8864,
                                                         $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER)};
