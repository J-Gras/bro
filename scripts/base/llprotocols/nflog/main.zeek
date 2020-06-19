module LL_NFLOG;

const DLT_NFLOG : count = 239;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_NFLOG,
                                                         $analyzer=LLAnalyzer::LLANALYZER_NFLOGANALYZER)};
