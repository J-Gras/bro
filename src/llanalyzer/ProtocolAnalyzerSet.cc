#include "ProtocolAnalyzerSet.h"

namespace llanalyzer {

ProtocolAnalyzerSet::ProtocolAnalyzerSet(Config& configuration, const std::string& defaultAnalyzerName) {
    // Instantiate objects for all analyzers
    for (const auto& currentDispatcherConfig : configuration.getDispatchers()) {
        for (const auto& currentMapping : currentDispatcherConfig.getMappings()) {
            // Check if already instantiated
            if (analyzers.count(currentMapping.second) != 0) {
                continue;
            }

            // Check if analyzer exists
            Analyzer* newAnalyzer = llanalyzer_mgr->InstantiateAnalyzer(currentMapping.second);
            if (newAnalyzer != nullptr) {
                analyzers.emplace(currentMapping.second, newAnalyzer);
            }
        }
    }

    // Generate Dispatchers, starting at root
    rootDispatcher = getDispatcher(configuration, "ROOT");
    if (rootDispatcher == nullptr) {
        reporter->InternalError("No dispatching configuration for ROOT of llanalyzer set.");
    }


    // Set up default analysis
    defaultDispatcher = nullptr;
    defaultAnalyzer = (analyzers.count(defaultAnalyzerName) != 0) ?
                      analyzers[defaultAnalyzerName] : llanalyzer_mgr->InstantiateAnalyzer(defaultAnalyzerName);
    if ( defaultAnalyzer != nullptr ) {
        defaultDispatcher = getDispatcher(configuration, defaultAnalyzerName);
    }

    currentState = rootDispatcher;
}

ProtocolAnalyzerSet::~ProtocolAnalyzerSet() {
    bool deleteDefault = defaultAnalyzer != nullptr;
    for (const auto& current : analyzers) {
        if (current.second == defaultAnalyzer)
            deleteDefault = false;
        delete current.second;
    }
    if (deleteDefault) delete defaultAnalyzer;
}

Analyzer* ProtocolAnalyzerSet::dispatch(identifier_t identifier) {
    // Because leaf nodes (aka no more dispatching) can still have an existing analyzer that returns more identifiers,
    // currentState needs to be checked to be not null. In this case there would have been an analyzer dispatched
    // in the last layer, but no dispatcher for it (end of FSM)
    const Value* result = (currentState != nullptr) ? currentState->Lookup(identifier) : nullptr;

    if (result == nullptr ) {
        if ( currentState != defaultDispatcher ) {
            // Switch to default analysis once
            currentState = defaultDispatcher;
            return defaultAnalyzer;
        }
        return nullptr;
    } else {
        currentState = result->dispatcher;
        return result->analyzer;
    }
}

void ProtocolAnalyzerSet::reset() {
    currentState = rootDispatcher;
}

void ProtocolAnalyzerSet::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "ProtocolAnalyzerSet FSM:");
    for (const auto& current : dispatchers) {
        DBG_LOG(DBG_LLPOC, "  Dispatcher (%p): %s", current.second, current.first.c_str());
        current.second->DumpDebug();
    }
#endif
}

Dispatcher* ProtocolAnalyzerSet::getDispatcher(Config& configuration, const std::string& dispatcherName) {
    // Is it already created?
    if (dispatchers.count(dispatcherName) != 0) {
        return dispatchers[dispatcherName];
    }

    // Create new dispatcher from config
    std::optional<std::reference_wrapper<DispatcherConfig>> dispatcherConfig = configuration.getDispatcherConfig(dispatcherName);
    if (!dispatcherConfig) {
        // No such dispatcher found, this is therefore implicitly a leaf
        return nullptr;
    }
    const auto& mappings = dispatcherConfig->get().getMappings();

    Dispatcher* dispatcher = new dispatcher_impl();
    for (const auto& currentMapping : mappings) {
        // No analyzer with this name. Report warning and ignore.
        if (analyzers.count(currentMapping.second) == 0) {
            reporter->InternalWarning("No analyzer %s found for dispatching identifier %#x of %s, ignoring.",
                    currentMapping.second.c_str(),
                    currentMapping.first,
                    dispatcherName.c_str());
            continue;
        }

        dispatcher->Register(currentMapping.first, analyzers.at(currentMapping.second), getDispatcher(configuration, currentMapping.second));
    }
    dispatchers.emplace(dispatcherName, dispatcher);

    return dispatcher;
}

} // end of llanalyzer namespace
