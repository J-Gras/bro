#pragma once

#include "Dict.h"
#include "Dispatcher.h"

namespace zeek::llanalyzer {

class DictDispatcher : public Dispatcher	{
public:
	~DictDispatcher() override;

	bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
	Value* Lookup(identifier_t identifier) const override;
	size_t Size() const override;
	void Clear() override;

	void DumpDebug() const override;

private:

	PDict<Value> table;

};
}
