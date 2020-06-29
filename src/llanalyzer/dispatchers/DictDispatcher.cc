#include "DictDispatcher.h"

namespace zeek::llanalyzer {

DictDispatcher::~DictDispatcher()
	{
	Clear();
	}

bool DictDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher)
	{
	HashKey* key = new HashKey(identifier);
	table.Insert(key, new Value(analyzer, dispatcher));
	return true;
	}

Value* DictDispatcher::Lookup(identifier_t identifier) const
	{
	HashKey* key = new HashKey(identifier);
	Value* v = table.Lookup(key);
	delete key;
	return v;
	}

size_t DictDispatcher::Size() const
	{
	return table.Length();
	}

void DictDispatcher::Clear()
	{
	table.Clear();
	}

void DictDispatcher::DumpDebug() const
	{
#ifdef DEBUG
	//DBG_LOG(DBG_LLANALYZER, "  Dispatcher elements (used/total): %lu/%lu", Size(), ?);
	auto c = table.InitForIteration();
	HashKey* k;
	while ( Value* entry = table.NextEntry(k, c) )
		{
		const identifier_t* id = reinterpret_cast<const identifier_t*>(k->Key());
		DBG_LOG(DBG_LLANALYZER, "    %#8x => %s, %p", *id, entry->analyzer->GetAnalyzerName(), entry->dispatcher);
		}
#endif
	}

}
