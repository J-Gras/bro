type LLAnalyzerConfigEntry : record {
    # The parent analyzer's name. This analyzer will check for the identifier in the
    # packet data to know whether to call the next analyzer.
    parent : string;

    # A numeric identifier that can be found in the packet data that denotes an
    # analyzer should be called.
    identifier : count;

    # The name of the analyzer that matches the above identifier.
    analyzer : string;
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
    [$parent="ROOT", $identifier=DLT_EN10MB, $analyzer="EthernetAnalyzer"],
    [$parent="ROOT", $identifier=DLT_PPP_SERIAL, $analyzer="PPPSerialAnalyzer"],
    [$parent="ROOT", $identifier=DLT_IEEE802_11, $analyzer="IEEE802_11Analyzer"],
    [$parent="ROOT", $identifier=DLT_IEEE802_11_RADIO, $analyzer="IEEE802_11_RadioAnalyzer"],
    [$parent="ROOT", $identifier=DLT_FDDI, $analyzer="FDDIAnalyzer"],
    [$parent="ROOT", $identifier=DLT_NFLOG, $analyzer="NFLogAnalyzer"],
    [$parent="ROOT", $identifier=DLT_NULL, $analyzer="NullAnalyzer"],
    [$parent="ROOT", $identifier=DLT_LINUX_SLL, $analyzer="LinuxSLLAnalyzer"],

    [$parent="DefaultAnalyzer", $identifier=4, $analyzer="IPv4Analyzer"],
    [$parent="DefaultAnalyzer", $identifier=6, $analyzer="IPv6Analyzer"],

    [$parent="EthernetAnalyzer", $identifier=0x8847, $analyzer="MPLSAnalyzer"],
    [$parent="EthernetAnalyzer", $identifier=0x0800, $analyzer="IPv4Analyzer"],
    [$parent="EthernetAnalyzer", $identifier=0x86DD, $analyzer="IPv6Analyzer"],
    [$parent="EthernetAnalyzer", $identifier=0x0806, $analyzer="ARPAnalyzer"],
    [$parent="EthernetAnalyzer", $identifier=0x8035, $analyzer="ARPAnalyzer"],
    [$parent="EthernetAnalyzer", $identifier=0x8864, $analyzer="PPPoEAnalyzer"],

    [$parent="PPPoEAnalyzer", $identifier=0x0021, $analyzer="IPv4Analyzer"],
    [$parent="PPPoEAnalyzer", $identifier=0x0057, $analyzer="IPv6Analyzer"],

    [$parent="IEEE802_11_RadioAnalyzer", $identifier=DLT_IEEE802_11, $analyzer="IEEE802_11Analyzer"],

    [$parent="PPPSerialAnalyzer", $identifier=0x0281, $analyzer="MPLSAnalyzer"],
    [$parent="PPPSerialAnalyzer", $identifier=0x0021, $analyzer="IPv4Analyzer"],
    [$parent="PPPSerialAnalyzer", $identifier=0x0057, $analyzer="IPv6Analyzer"],

    [$parent="IEEE802_11Analyzer", $identifier=0x0800, $analyzer="IPv4Analyzer"],
    [$parent="IEEE802_11Analyzer", $identifier=0x86DD, $analyzer="IPv6Analyzer"],
    [$parent="IEEE802_11Analyzer", $identifier=0x0806, $analyzer="ARPAnalyzer"],
    [$parent="IEEE802_11Analyzer", $identifier=0x8035, $analyzer="ARPAnalyzer"],

    [$parent="NFLogAnalyzer", $identifier=AF_INET, $analyzer="IPv4Analyzer"],
    [$parent="NFLogAnalyzer", $identifier=AF_INET6, $analyzer="IPv6Analyzer"],

    [$parent="NullAnalyzer", $identifier=AF_INET, $analyzer="IPv4Analyzer"],

    ## From the Wireshark Wiki: "AF_INET6, unfortunately, has
    ## different values in {NetBSD,OpenBSD,BSD/OS},
    ## {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
    ## packet might have a link-layer header with 24, 28, or 30
    ## as the AF_ value." As we may be reading traces captured on
    ## platforms other than what we're running on, we accept them
    ## all here.
    [$parent="NullAnalyzer", $identifier=24, $analyzer="IPv6Analyzer"],
    [$parent="NullAnalyzer", $identifier=28, $analyzer="IPv6Analyzer"],
    [$parent="NullAnalyzer", $identifier=30, $analyzer="IPv6Analyzer"],

    [$parent="LinuxSLLAnalyzer", $identifier=0x0800, $analyzer="IPv4Analyzer"],
    [$parent="LinuxSLLAnalyzer", $identifier=0x86DD, $analyzer="IPv6Analyzer"],
    [$parent="LinuxSLLAnalyzer", $identifier=0x0806, $analyzer="ARPAnalyzer"],

    # RARP
    [$parent="LinuxSLLAnalyzer", $identifier=0x8035, $analyzer="ARPAnalyzer"]
];
