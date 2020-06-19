module LL_PPP_SERIAL;

const DLT_PPP_SERIAL : count = 50;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_PPP_SERIAL,
                                                         $analyzer=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER)};
