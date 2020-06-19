module LL_NULL;

const DLT_NULL : count = 0;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_NULL,
                                                         $analyzer=LLAnalyzer::LLANALYZER_NULLANALYZER)};
