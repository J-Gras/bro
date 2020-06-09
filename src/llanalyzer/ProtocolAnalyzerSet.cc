#include "ProtocolAnalyzerSet.h"

namespace zeek::llanalyzer {

ProtocolAnalyzerSet::ProtocolAnalyzerSet(Config& configuration, const std::string& default_analyzer_name)
	{
	// Instantiate objects for all analyzers
	for ( const auto& current_dispatcher_config : configuration.GetDispatchers() )
		{
		for ( const auto& current_mapping : current_dispatcher_config.GetMappings() )
			{
			// Check if already instantiated
			if ( analyzers.count(current_mapping.second) != 0 )
				continue;

			// Check if analyzer exists
			if ( Analyzer* newAnalyzer = llanalyzer_mgr->InstantiateAnalyzer(current_mapping.second) )
				analyzers.emplace(current_mapping.second, newAnalyzer);
			}
		}

	// Generate Dispatchers, starting at root
	root_dispatcher = GetDispatcher(configuration, "ROOT");
	if ( root_dispatcher == nullptr )
		reporter->InternalError("No dispatching configuration for ROOT of llanalyzer set.");

	// Set up default analysis
	default_dispatcher = nullptr;
	default_analyzer = (analyzers.count(default_analyzer_name) != 0) ? analyzers[default_analyzer_name] : llanalyzer_mgr->InstantiateAnalyzer(default_analyzer_name);
	if ( default_analyzer != nullptr )
		default_dispatcher = GetDispatcher(configuration, default_analyzer_name);

	current_state = root_dispatcher;
	}

ProtocolAnalyzerSet::~ProtocolAnalyzerSet()
	{
	bool delete_default = default_analyzer != nullptr;
	for ( const auto& current : analyzers )
		{
		if ( current.second == default_analyzer )
			delete_default = false;

		delete current.second;
		}

	if ( delete_default )
		delete default_analyzer;
	}

Analyzer* ProtocolAnalyzerSet::Dispatch(identifier_t identifier)
	{
	// Because leaf nodes (aka no more dispatching) can still have an existing analyzer that returns more identifiers,
	// current_state needs to be checked to be not null. In this case there would have been an analyzer dispatched
	// in the last layer, but no dispatcher for it (end of FSM)
	const Value* result = (current_state != nullptr) ? current_state->Lookup(identifier) : nullptr;

	if ( result == nullptr )
		{
		if ( current_state != default_dispatcher )
			{
			// Switch to default analysis once
			current_state = default_dispatcher;
			return default_analyzer;
			}
		return nullptr;
		}
	else
		{
		current_state = result->dispatcher;
		return result->analyzer;
		}
	}

void ProtocolAnalyzerSet::Reset()
	{
	current_state = root_dispatcher;
	}

void ProtocolAnalyzerSet::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_LLPOC, "ProtocolAnalyzerSet FSM:");
	for ( const auto& current : dispatchers )
		{
		DBG_LOG(DBG_LLPOC, "  Dispatcher (%p): %s", current.second, current.first.c_str());
		current.second->DumpDebug();
		}
#endif
	}

Dispatcher* ProtocolAnalyzerSet::GetDispatcher(Config& configuration, const std::string& dispatcher_name)
	{
	// Is it already created?
	if ( dispatchers.count(dispatcher_name) != 0 )
		return dispatchers[dispatcher_name];

	// Create new dispatcher from config
	std::optional<std::reference_wrapper<DispatcherConfig>> dispatcher_config = configuration.GetDispatcherConfig(dispatcher_name);
	if ( ! dispatcher_config )
		// No such dispatcher found, this is therefore implicitly a leaf
		return nullptr;

	const auto& mappings = dispatcher_config->get().GetMappings();

	Dispatcher* dispatcher = new dispatcher_impl();
	for ( const auto& current_mapping : mappings )
		{
		// No analyzer with this name. Report warning and ignore.
		if ( analyzers.count(current_mapping.second) == 0 )
			{
			reporter->InternalWarning("No analyzer %s found for dispatching identifier %#x of %s, ignoring.",
			                          current_mapping.second.c_str(),
			                          current_mapping.first,
			                          dispatcher_name.c_str());
			continue;
			}

		dispatcher->Register(current_mapping.first, analyzers.at(current_mapping.second), GetDispatcher(configuration, current_mapping.second));
		}

	dispatchers.emplace(dispatcher_name, dispatcher);

	return dispatcher;
	}

}
