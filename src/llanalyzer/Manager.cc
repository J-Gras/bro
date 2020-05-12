// See the file "COPYING" in the main distribution directory for copyright.

#include <pcap.h>
#include <list>

#include "Manager.h"
#include "Config.h"
#include "ProtocolAnalyzerSet.h"
#include "plugin/Manager.h"
#include "NetVar.h"

using namespace llanalyzer;

Manager::Manager()
        : plugin::ComponentManager<llanalyzer::Tag, llanalyzer::Component>("LLAnalyzer", "Tag"),
          analyzerSet(nullptr) {
}

Manager::~Manager() {
    delete analyzerSet;
}

void Manager::InitPreScript() {
}

void Manager::InitPostScript() {
    // Read in configuration
    // TODO: just a mockup now, do for real

    // Configuration Mockup
    Config configuration;
    //configuration.addMapping("ROOT", DLT_EN10MB, "WrapperAnalyzer");
    configuration.addMapping("ROOT", DLT_EN10MB, "EthernetAnalyzer");
    configuration.addMapping("ROOT", DLT_PPP_SERIAL, "PPPSerialAnalyzer");
    configuration.addMapping("ROOT", DLT_IEEE802_11, "IEEE802_11Analyzer");
    configuration.addMapping("ROOT", DLT_IEEE802_11_RADIO, "IEEE802_11_RadioAnalyzer");
    configuration.addMapping("ROOT", DLT_NFLOG, "NFLogAnalyzer");
    //configuration.addMapping("ROOT", DLT_NULL, "NullAnalyzer");

    configuration.addMapping("EthernetAnalyzer", 0x8847, "MPLSAnalyzer");
    configuration.addMapping("IEEE802_11_RadioAnalyzer", DLT_IEEE802_11, "IEEE802_11Analyzer");

    configuration.addMapping("PPPSerialAnalyzer", 0x0281, "MPLSAnalyzer");
    configuration.addMapping("PPPSerialAnalyzer", 0x0021, "IPv4Analyzer");
    configuration.addMapping("PPPSerialAnalyzer", 0x0057, "IPv6Analyzer");

    configuration.addMapping("IEEE802_11Analyzer", 0x0800, "IPv4Analyzer");
    configuration.addMapping("IEEE802_11Analyzer", 0x86DD, "IPv6Analyzer");
    configuration.addMapping("IEEE802_11Analyzer", 0x0806, "ARPAnalyzer");
    configuration.addMapping("IEEE802_11Analyzer", 0x8035, "ARPAnalyzer"); //RARP

    configuration.addMapping("NFLogAnalyzer", AF_INET, "IPv4Analyzer");
    configuration.addMapping("NFLogAnalyzer", AF_INET6, "IPv6Analyzer");

    configuration.addMapping("NullAnalyzer", AF_INET, "IPv4Analyzer");
    // From the Wireshark Wiki: "AF_INET6, unfortunately, has
    // different values in {NetBSD,OpenBSD,BSD/OS},
    // {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
    // packet might have a link-layer header with 24, 28, or 30
    // as the AF_ value." As we may be reading traces captured on
    // platforms other than what we're running on, we accept them
    // all here.
    configuration.addMapping("NullAnalyzer", 24, "IPv6Analyzer");
    configuration.addMapping("NullAnalyzer", 28, "IPv6Analyzer");
    configuration.addMapping("NullAnalyzer", 30, "IPv6Analyzer");

    analyzerSet = new ProtocolAnalyzerSet(configuration);
}

void Manager::Done() {
}

void Manager::DumpDebug() {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "Available llanalyzers after zeek_init():");
    for (auto& current : GetComponents()) {
        DBG_LOG(DBG_LLPOC, "    %s (%s)", current->Name().c_str(), IsEnabled(current->Tag()) ? "enabled" : "disabled");
    }

    // Dump Analyzer Set
    analyzerSet->DumpDebug();
#endif
}

bool Manager::EnableAnalyzer(const Tag& tag) {
    Component *p = Lookup(tag);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
    p->SetEnabled(true);

    return true;
}

bool Manager::EnableAnalyzer(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
    p->SetEnabled(true);

    return true;
}

bool Manager::DisableAnalyzer(const Tag& tag) {
    Component *p = Lookup(tag);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
    p->SetEnabled(false);

    return true;
}

bool Manager::DisableAnalyzer(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
    p->SetEnabled(false);

    return true;
}

void Manager::DisableAllAnalyzers() {
    DBG_LOG(DBG_LLPOC, "Disabling all analyzers");

    list<Component *> all_analyzers = GetComponents();
    for (auto i = all_analyzers.begin(); i != all_analyzers.end(); ++i)
        (*i)->SetEnabled(false);
}

llanalyzer::Tag Manager::GetAnalyzerTag(const char *name) {
    return GetComponentTag(name);
}

bool Manager::IsEnabled(Tag tag) {
    if (!tag)
        return false;

    Component *p = Lookup(tag);

    if (!p)
        return false;

    return p->Enabled();
}

bool Manager::IsEnabled(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    return p->Enabled();
}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag) {
    Component* c = Lookup(tag);

    if (!c) {
        reporter->InternalWarning("request to instantiate unknown llanalyzer");
        return nullptr;
    }

    if (!c->Enabled()) return nullptr;

    if (!c->Factory()) {
        reporter->InternalWarning("analyzer %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
        return nullptr;
    }

    Analyzer* a = c->Factory()();

    if (!a) {
        reporter->InternalWarning("analyzer instantiation failed");
        return nullptr;
    }

    if (tag != a->GetAnalyzerTag()) {
        reporter->InternalError("Mismatch of requested analyzer %s and instantiated analyzer %s. This usually means that the plugin author made a mistake.",
                GetComponentName(tag).c_str(), GetComponentName(a->GetAnalyzerTag()).c_str());
        return nullptr;
    }

    return a;
}

Analyzer* Manager::InstantiateAnalyzer(const std::string& name) {
    Tag tag = GetComponentTag(name);
    return tag ? InstantiateAnalyzer(tag) : nullptr;
}

void Manager::processPacket(Packet* packet) {
#ifdef DEBUG
    static size_t counter = 0;
    DBG_LOG(DBG_LLPOC, "Analyzing packet %ld, ts=%.3f...", ++counter, packet->time);
#endif
    // Dispatch and analyze layers
    AnalyzerResult result = AnalyzerResult::Continue;
    identifier_t nextLayerId = packet->link_type;
    do {
        Analyzer* currentAnalyzer = analyzerSet->dispatch(nextLayerId);

        // Analyzer not found
        if (currentAnalyzer == nullptr) {
            //TODO: Fallback to IP or generate weird
            break;
        }

        // Analyze this layer and get identifier of next layer protocol
        std::tie(result, nextLayerId) = currentAnalyzer->analyze(packet);

#ifdef DEBUG
        switch ( result ) {
            case AnalyzerResult::Continue:
                DBG_LOG(DBG_LLPOC, "Analysis in %s succeded, next layer identifier is %#x.",
                        currentAnalyzer->GetAnalyzerName(), nextLayerId);
                break;
            case AnalyzerResult::Terminate:
                DBG_LOG(DBG_LLPOC, "Done, last found layer identifier was %#x.", nextLayerId);
                break;
            default:
                DBG_LOG(DBG_LLPOC, "Analysis failed in %s", currentAnalyzer->GetAnalyzerName());
        }
#endif

    } while (result == AnalyzerResult::Continue);

    if ( result == AnalyzerResult::Terminate ) {
        CustomEncapsulationSkip(packet);
    }

    // Processing finished, reset analyzer set state for next packet
    analyzerSet->reset();
}

void Manager::CustomEncapsulationSkip(Packet *packet) {
    if (encap_hdr_size) {
        auto pdata = packet->cur_pos;

        // Blanket encapsulation. We assume that what remains is IP.
        if (pdata + encap_hdr_size + sizeof(struct ip) >= packet->GetEndOfData()) {
            packet->Weird("no_ip_left_after_encap");
            return;
        }

        pdata += encap_hdr_size;

        auto ip = (const struct ip *) pdata;

        switch ( ip->ip_v )
            {
            case 4: packet->l3_proto = L3_IPV4; break;
            case 6: packet->l3_proto = L3_IPV6; break;
            default:
                {
                // Neither IPv4 nor IPv6.
                packet->Weird("no_ip_in_encap");
                return;
                }
            }
    }
}
