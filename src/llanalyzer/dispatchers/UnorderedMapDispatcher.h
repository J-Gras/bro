#pragma once

#include <unordered_map>
#include "Dispatcher.h"

namespace zeek::llanalyzer {

class UnorderedMapDispatcher : public Dispatcher {
public:
	~UnorderedMapDispatcher() override;

	bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
	void Register(const register_map& data) override;
	const Value* Lookup(identifier_t identifier) const override;
	size_t Size() const override;
	void Clear() override;

	void DumpDebug() const override;

private:
	std::unordered_map<identifier_t, Value*> table;

	inline bool ContainsBucketCollision()
		{
		for ( size_t bucket = 0; bucket < table.bucket_count(); bucket++ )
			{
			if ( table.bucket_size(bucket) > 1 )
				return true;
			}

		return false;
		}
};

}
