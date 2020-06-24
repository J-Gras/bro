module LL_LINUX_SLL;

const DLT_LINUX_SLL : count = 113;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_LINUX_SLL,
                                                         $analyzer=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x0800,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x86DD,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x0806,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};

   # RARP
redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER,
                                                         $identifier=0x8035,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER)};
