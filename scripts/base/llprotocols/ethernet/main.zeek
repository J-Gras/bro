module LL_ETHERNET;

const DLT_EN10MB : count = 1;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_EN10MB,
                                                         $analyzer=LLAnalyzer::LLANALYZER_ETHERNETANALYZER)};
