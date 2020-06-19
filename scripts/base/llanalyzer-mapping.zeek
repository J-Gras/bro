type LLAnalyzerConfigEntry : record {
    # The parent analyzer's name. This analyzer will check for the identifier in the
    # packet data to know whether to call the next analyzer. This field is optional.
    # If it is not included, the identifier will attach to the "root" analyzer. This
    # means that the identifier will be searched for the initial packet header instead
    # of later headers.
    parent : LLAnalyzer::Tag &optional;

    # A numeric identifier that can be found in the packet data that denotes an
    # analyzer should be called.
    identifier : count;

    # The name of the analyzer that matches the above identifier.
    analyzer : LLAnalyzer::Tag;
};

# These are defined in libpcap, but we need them for the default configuration below.
const DLT_NULL : count = 0;
const DLT_EN10MB : count = 1;
const DLT_FDDI : count = 10;
const DLT_PPP_SERIAL : count = 50;
const DLT_IEEE802_11 : count = 105;
const DLT_LINUX_SLL : count = 113;
const DLT_IEEE802_11_RADIO : count = 127;
const DLT_NFLOG : count = 239;

const AF_INET  : count = 2;
const AF_INET6 : count = 10;

global llanalyzer_mapping : vector of LLAnalyzerConfigEntry = [
    [$identifier=DLT_EN10MB, $analyzer=LLAnalyzer::LLANALYZER_ETHERNETANALYZER],
    [$identifier=DLT_PPP_SERIAL, $analyzer=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER],
    [$identifier=DLT_IEEE802_11, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER],
    [$identifier=DLT_IEEE802_11_RADIO, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11_RADIOANALYZER],
    [$identifier=DLT_FDDI, $analyzer=LLAnalyzer::LLANALYZER_FDDIANALYZER],
    [$identifier=DLT_NFLOG, $analyzer=LLAnalyzer::LLANALYZER_NFLOGANALYZER],
    [$identifier=DLT_NULL, $analyzer=LLAnalyzer::LLANALYZER_NULLANALYZER],
    [$identifier=DLT_LINUX_SLL, $analyzer=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_DEFAULTANALYZER, $identifier=4, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_DEFAULTANALYZER, $identifier=6, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x8847, $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x8100, $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x88A8, $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x9100, $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_ETHERNETANALYZER, $identifier=0x8864, $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8847, $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8100, $analyzer=LLAnalyzer::LLANALYZER_VLANANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_VLANANALYZER, $identifier=0x8864, $analyzer=LLAnalyzer::LLANALYZER_PPPOEANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_PPPOEANALYZER, $identifier=0x0021, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_PPPOEANALYZER, $identifier=0x0057, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_IEEE802_11_RADIOANALYZER, $identifier=DLT_IEEE802_11, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER, $identifier=0x0281, $analyzer=LLAnalyzer::LLANALYZER_MPLSANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER, $identifier=0x0021, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_PPPSERIALANALYZER, $identifier=0x0057, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_IEEE802_11ANALYZER, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_NFLOGANALYZER, $identifier=AF_INET, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_NFLOGANALYZER, $identifier=AF_INET6, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_NULLANALYZER, $identifier=AF_INET, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],

    ## From the Wireshark Wiki: "AF_INET6, unfortunately, has
    ## different values in {NetBSD,OpenBSD,BSD/OS},
    ## {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
    ## packet might have a link-layer header with 24, 28, or 30
    ## as the AF_ value." As we may be reading traces captured on
    ## platforms other than what we're running on, we accept them
    ## all here.
    [$parent=LLAnalyzer::LLANALYZER_NULLANALYZER, $identifier=24, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_NULLANALYZER, $identifier=28, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_NULLANALYZER, $identifier=30, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],

    [$parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6ANALYZER],
    [$parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER],

    # RARP
    [$parent=LLAnalyzer::LLANALYZER_LINUXSLLANALYZER, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARPANALYZER]
];
