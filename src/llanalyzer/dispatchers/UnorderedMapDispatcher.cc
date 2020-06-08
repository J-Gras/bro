#include "UnorderedMapDispatcher.h"

namespace zeek::llanalyzer {

UnorderedMapDispatcher::~UnorderedMapDispatcher()
	{
	Clear();
	}

bool UnorderedMapDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher)
	{
	auto* new_value = new Value(analyzer, dispatcher);
	if ( ! table.emplace(identifier, new_value).second )
		{
		delete new_value;
		return false;
		}

	// If there is a bucket collision, rehash
	while ( ContainsBucketCollision() )
		table.rehash(table.bucket_count() + 100);

	return true;
	}

void UnorderedMapDispatcher::Register(const register_map& data)
	{
	for ( auto& current : data )
		{
		auto* new_value = new Value(current.second.first, current.second.second);
		if ( ! table.emplace(current.first, new_value).second )
			{
			delete new_value;
			throw std::invalid_argument("Analyzer already registered!");
			}
		}

	// If there is a bucket collision, rehash
	while ( ContainsBucketCollision() )
		table.rehash(table.bucket_count() + 100);
	}

const Value* UnorderedMapDispatcher::Lookup(identifier_t identifier) const
	{
	if ( table.count(identifier) != 0 )
		return table.at(identifier);

	return nullptr;
	}

size_t UnorderedMapDispatcher::Size() const
	{
	return table.size();
	}

void UnorderedMapDispatcher::Clear()
	{
	for ( const auto& current : table )
		delete current.second;

	table.clear();
	}

void UnorderedMapDispatcher::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_LLPOC, "  Dispatcher elements (used/total): %lu/%lu", Size(), table.bucket_count());
	for ( const auto& current : table )
		{
		DBG_LOG(DBG_LLPOC, "    %#8x => %s, %p", current.first, current.second->analyzer->GetAnalyzerName(), current.second->dispatcher);
		}
#endif
	}

	}
