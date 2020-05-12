#pragma once

#include <cstdint>
#include <string>
#include <map>

namespace llanalyzer {
    using identifier_t = uint32_t;

    /**
     * Result of low layer analysis.
     */
    enum class AnalyzerResult {
        Failed,   // Analysis failed
        Continue, // Analysis succeded and an encapuslated protocol was determined
        Terminate // Analysis succeded and there is no further analysis to do
    };
}