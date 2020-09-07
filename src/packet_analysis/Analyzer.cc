// See the file "COPYING" in the main distribution directory for copyright.

#include "Analyzer.h"

#include "DebugLogger.h"

namespace zeek::packet_analysis {

Analyzer::Analyzer(std::string name)
	{
	Tag t = packet_mgr->GetComponentTag(name);

	if ( ! t )
		reporter->InternalError("unknown packet_analysis name %s", name.c_str());

	Init(t);
	}

Analyzer::Analyzer(const Tag& tag)
	{
	Init(tag);
	}

void Analyzer::Init(const Tag& _tag)
	{
	tag = _tag;
	}

const Tag Analyzer::GetAnalyzerTag() const
	{
	assert(tag);
	return tag;
	}

const char* Analyzer::GetAnalyzerName() const
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag).c_str();
	}

bool Analyzer::IsAnalyzer(const char* name)
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag) == name;
	}

void Analyzer::RegisterAnalyzerMapping(uint32_t identifier, AnalyzerPtr analyzer)
	{
	dispatcher.Register(identifier, std::move(analyzer));
	}

void Analyzer::RegisterDefaultAnalyzer(AnalyzerPtr default_analyzer)
	{
	this->default_analyzer = std::move(default_analyzer);
	}

AnalyzerPtr Analyzer::Lookup(uint32_t identifier) const
	{
	return dispatcher.Lookup(identifier);
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet,
		uint32_t identifier) const
	{
	auto inner_analyzer = Lookup(identifier);
	if ( ! inner_analyzer )
		inner_analyzer = default_analyzer;

	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), identifier);
		packet->Weird("no_suitable_analyzer_found");
		return false;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), identifier);
	return inner_analyzer->AnalyzePacket(len, data, packet);
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const
	{
	if ( default_analyzer )
		return default_analyzer->AnalyzePacket(len, data, packet);

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s stopped, no default analyzer available.",
			GetAnalyzerName());
	packet->Weird("no_suitable_analyzer_found");
	return true;
	}

void Analyzer::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "Debug info for %s", this->GetAnalyzerName());
	dispatcher.DumpDebug();
#endif
	}

}
