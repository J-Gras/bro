module LL_IEEE802_11_RADIO;

const DLT_IEEE802_11_RADIO : count = 127;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_IEEE802_11_RADIO,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11_RADIOANALYZER)};
