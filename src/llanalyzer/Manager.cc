// See the file "COPYING" in the main distribution directory for copyright.

#include <list>
#include <pcap.h>

#include "Config.h"
#include "Manager.h"
#include "NetVar.h"
#include "ProtocolAnalyzerSet.h"
#include "plugin/Manager.h"

using namespace zeek::llanalyzer;

Manager::Manager()
	: plugin::ComponentManager<llanalyzer::Tag, llanalyzer::Component>("LLAnalyzer", "Tag")
	{
	}

Manager::~Manager()
	{
	delete analyzer_set;
	}

void Manager::InitPostScript()
	{
	// Read in configuration
	// TODO: just a mockup now, do for real
	Config configuration;
	//configuration.AddMapping("ROOT", DLT_EN10MB, "WrapperAnalyzer");
	configuration.AddMapping("ROOT", DLT_EN10MB, "EthernetAnalyzer");
	configuration.AddMapping("ROOT", DLT_PPP_SERIAL, "PPPSerialAnalyzer");
	configuration.AddMapping("ROOT", DLT_IEEE802_11, "IEEE802_11Analyzer");
	configuration.AddMapping("ROOT", DLT_IEEE802_11_RADIO, "IEEE802_11_RadioAnalyzer");
	configuration.AddMapping("ROOT", DLT_FDDI, "FDDIAnalyzer");
	configuration.AddMapping("ROOT", DLT_NFLOG, "NFLogAnalyzer");
	configuration.AddMapping("ROOT", DLT_NULL, "NullAnalyzer");
	configuration.AddMapping("ROOT", DLT_LINUX_SLL, "LinuxSLLAnalyzer");

	configuration.AddMapping("DefaultAnalyzer", 4, "IPv4Analyzer");
	configuration.AddMapping("DefaultAnalyzer", 6, "IPv6Analyzer");

	configuration.AddMapping("EthernetAnalyzer", 0x8847, "MPLSAnalyzer");
	configuration.AddMapping("IEEE802_11_RadioAnalyzer", DLT_IEEE802_11, "IEEE802_11Analyzer");

	configuration.AddMapping("PPPSerialAnalyzer", 0x0281, "MPLSAnalyzer");
	configuration.AddMapping("PPPSerialAnalyzer", 0x0021, "IPv4Analyzer");
	configuration.AddMapping("PPPSerialAnalyzer", 0x0057, "IPv6Analyzer");

	configuration.AddMapping("IEEE802_11Analyzer", 0x0800, "IPv4Analyzer");
	configuration.AddMapping("IEEE802_11Analyzer", 0x86DD, "IPv6Analyzer");
	configuration.AddMapping("IEEE802_11Analyzer", 0x0806, "ARPAnalyzer");
	configuration.AddMapping("IEEE802_11Analyzer", 0x8035, "ARPAnalyzer"); //RARP

	configuration.AddMapping("NFLogAnalyzer", AF_INET, "IPv4Analyzer");
	configuration.AddMapping("NFLogAnalyzer", AF_INET6, "IPv6Analyzer");

	configuration.AddMapping("NullAnalyzer", AF_INET, "IPv4Analyzer");
	// From the Wireshark Wiki: "AF_INET6, unfortunately, has
	// different values in {NetBSD,OpenBSD,BSD/OS},
	// {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
	// packet might have a link-layer header with 24, 28, or 30
	// as the AF_ value." As we may be reading traces captured on
	// platforms other than what we're running on, we accept them
	// all here.
	configuration.AddMapping("NullAnalyzer", 24, "IPv6Analyzer");
	configuration.AddMapping("NullAnalyzer", 28, "IPv6Analyzer");
	configuration.AddMapping("NullAnalyzer", 30, "IPv6Analyzer");

	configuration.AddMapping("LinuxSLLAnalyzer", 0x0800, "IPv4Analyzer");
	configuration.AddMapping("LinuxSLLAnalyzer", 0x86DD, "IPv6Analyzer");
	configuration.AddMapping("LinuxSLLAnalyzer", 0x0806, "ARPAnalyzer");
	configuration.AddMapping("LinuxSLLAnalyzer", 0x8035, "ARPAnalyzer"); //RARP

	analyzer_set = new ProtocolAnalyzerSet(configuration, "DefaultAnalyzer");
	}

void Manager::Done()
	{
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_LLPOC, "Available llanalyzers after zeek_init():");
	for ( auto& current : GetComponents() )
		{
		DBG_LOG(DBG_LLPOC, "    %s (%s)", current->Name().c_str(), IsEnabled(current->Tag()) ? "enabled" : "disabled");
		}

	// Dump Analyzer Set
	analyzer_set->DumpDebug();
#endif
	}

bool Manager::EnableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::EnableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

void Manager::DisableAllAnalyzers()
	{
	DBG_LOG(DBG_LLPOC, "Disabling all analyzers");

	std::list<Component*> all_analyzers = GetComponents();
	for ( const auto& analyzer : all_analyzers )
		analyzer->SetEnabled(false);
	}

zeek::llanalyzer::Tag Manager::GetAnalyzerTag(const char* name)
	{
	return GetComponentTag(name);
	}

bool Manager::IsEnabled(Tag tag)
	{
	if ( ! tag )
		return false;

	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	return p->Enabled();
	}

bool Manager::IsEnabled(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	return p->Enabled();
	}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("request to instantiate unknown llanalyzer");
		return nullptr;
		}

	if ( ! c->Enabled() )
		return nullptr;

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
		return nullptr;
		}

	Analyzer* a = c->Factory()();

	if ( ! a )
		{
		reporter->InternalWarning("analyzer instantiation failed");
		return nullptr;
		}

	if ( tag != a->GetAnalyzerTag() )
		{
		reporter->InternalError("Mismatch of requested analyzer %s and instantiated analyzer %s. This usually means that the plugin author made a mistake.",
								GetComponentName(tag).c_str(), GetComponentName(a->GetAnalyzerTag()).c_str());
		return nullptr;
		}

	return a;
	}

Analyzer* Manager::InstantiateAnalyzer(const std::string& name)
	{
	Tag tag = GetComponentTag(name);
	return tag ? InstantiateAnalyzer(tag) : nullptr;
	}

void Manager::processPacket(Packet* packet)
	{
#ifdef DEBUG
	static size_t counter = 0;
	DBG_LOG(DBG_LLPOC, "Analyzing packet %ld, ts=%.3f...", ++counter, packet->time);
#endif
	// Dispatch and analyze layers
	AnalyzerResult result = AnalyzerResult::Continue;
	identifier_t next_layer_id = packet->link_type;
	do
		{
		auto current_analyzer = analyzer_set->Dispatch(next_layer_id);

		// Analyzer not found
		if ( current_analyzer == nullptr )
			break;

		// Analyze this layer and get identifier of next layer protocol
		std::tie(result, next_layer_id) = current_analyzer->Analyze(packet);

#ifdef DEBUG
		switch ( result )
			{
			case AnalyzerResult::Continue:
				DBG_LOG(DBG_LLPOC, "Analysis in %s succeded, next layer identifier is %#x.",
					current_analyzer->GetAnalyzerName(), next_layer_id);
				break;
			case AnalyzerResult::Terminate:
				DBG_LOG(DBG_LLPOC, "Done, last found layer identifier was %#x.", next_layer_id);
				break;
			default:
				DBG_LOG(DBG_LLPOC, "Analysis failed in %s", current_analyzer->GetAnalyzerName());
			}
#endif

		} while ( result == AnalyzerResult::Continue );

	if ( result == AnalyzerResult::Terminate )
		CustomEncapsulationSkip(packet);

	// Processing finished, reset analyzer set state for next packet
	analyzer_set->Reset();
	}

void Manager::CustomEncapsulationSkip(Packet* packet)
	{
	if ( encap_hdr_size )
		{
		auto pdata = packet->cur_pos;

		// Blanket encapsulation. We assume that what remains is IP.
		if ( pdata + encap_hdr_size + sizeof(struct ip) >= packet->GetEndOfData() )
			{
			packet->Weird("no_ip_left_after_encap");
			return;
			}

		pdata += encap_hdr_size;

		auto ip = (const struct ip*)pdata;

		switch ( ip->ip_v )
			{
			case 4:
				packet->l3_proto = L3_IPV4;
				break;
			case 6:
				packet->l3_proto = L3_IPV6;
				break;
			default:
				{
				// Neither IPv4 nor IPv6.
				packet->Weird("no_ip_in_encap");
				return;
				}
			}
		}
	}
