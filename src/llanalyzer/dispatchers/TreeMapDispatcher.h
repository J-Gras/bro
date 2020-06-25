#pragma once

#include <map>
#include "Dispatcher.h"

namespace zeek::llanalyzer {

class TreeMapDispatcher : public Dispatcher	{
public:
	~TreeMapDispatcher() override;

	bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
	Value* Lookup(identifier_t identifier) const override;
	size_t Size() const override;
	void Clear() override;

	void DumpDebug() const override;

private:
	std::map<identifier_t, Value*> table;

};
}
