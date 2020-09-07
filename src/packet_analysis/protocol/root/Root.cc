// See the file "COPYING" in the main distribution directory for copyright.

#include "Root.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Root;

RootAnalyzer::RootAnalyzer()
	: zeek::packet_analysis::Analyzer("Root")
	{
	}

bool RootAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	reporter->InternalError("AnalysisPacket() was called for the root analyzer.");
	}