module LL_NULL;

const DLT_NULL : count = 0;
const AF_INET : count = 2;
const AF_INET6 : count = 10;

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($identifier=DLT_NULL,
                                                         $analyzer=LLAnalyzer::LLANALYZER_NULLANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NULLANALYZER,
                                                         $identifier=AF_INET,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER)};

## From the Wireshark Wiki: AF_INET6ANALYZER, unfortunately, has different values in
## {NetBSD,OpenBSD,BSD/OS}, {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
## packet might have a link-layer header with 24, 28, or 30 as the AF_ value. As we
## may be reading traces captured on platforms other than what we're running on, we
## accept them all here.
##
redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NULLANALYZER,
                                                         $identifier=24,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NULLANALYZER,
                                                         $identifier=28,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};

redef LLAnalyzer::config_map += {LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NULLANALYZER,
                                                         $identifier=30,
                                                         $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER)};
