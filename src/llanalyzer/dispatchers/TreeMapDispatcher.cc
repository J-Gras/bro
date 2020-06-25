#include "TreeMapDispatcher.h"

namespace zeek::llanalyzer {

TreeMapDispatcher::~TreeMapDispatcher()
	{
	FreeValues();
	}

bool TreeMapDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher)
	{
	return table.emplace(identifier, new Value(analyzer, dispatcher)).second;
	}

Value* TreeMapDispatcher::Lookup(identifier_t identifier) const
	{
	if ( table.count(identifier) != 0 )
		return table.at(identifier);
	else
		return nullptr;
	}

size_t TreeMapDispatcher::Size() const
	{
	return table.size();
	}

void TreeMapDispatcher::Clear()
	{
	FreeValues();
	table.clear();
	}

void TreeMapDispatcher::FreeValues()
	{
	for ( auto& current : table )
		{
		delete current.second;
		current.second = nullptr;
		}
	}

void TreeMapDispatcher::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_LLANALYZER, "  Dispatcher elements (used/total): %lu/%lu", Size(), table.size());
	for ( const auto& current : table )
		{
		DBG_LOG(DBG_LLANALYZER, "    %#8x => %s, %p", current.first, current.second->analyzer->GetAnalyzerName(), current.second->dispatcher);
		}
#endif
	}

}
