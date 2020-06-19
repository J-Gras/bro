module LL_LINUX_SLL;

const DLT_LINUX_SLL : count = 113;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_LINUX_SLL,
                                                         $analyzer=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER)};
