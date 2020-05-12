// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iosource/Packet.h>
#include "Tag.h"
#include "Defines.h"
#include "Manager.h"

namespace llanalyzer {

class Analyzer {
public:
	/**
	 * Constructor.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 */
	explicit Analyzer(std::string name);

	/**
	 * Constructor.
	 *
	 * @param tag The tag for the type of analyzer. The tag must map to
	 * the name the corresponding Component registers.
	 */
	explicit Analyzer(const Tag& tag);

	/**
	 * Destructor.
	 */
	virtual ~Analyzer();

	/**
	 * Returns the tag associated with the analyzer's type.
	 */
	const Tag GetAnalyzerTag() const;

	/**
	 * Returns a textual description of the analyzer's type. This is
	 * what's passed to the constructor and usally corresponds to the
	 * protocol name, e.g., "ARP".
	 */
	const char* GetAnalyzerName() const;

	/**
	 * Returns true if this analyzer's type matches the name passes in.
	 * This is shortcut for comparing GetAnalyzerName() with the given
	 * name.
	 *
	 * @param name The name to check.
	 */
	bool IsAnalyzer(const char* name);

	/**
	 * Analyzes the given packet. The analysis is supposed to start at cur_pos
	 * of the packet, which points to the so far unanalyzed part of the packet.
	 * If the analyzed protocol encapsulates another protocol, the packet's
	 * cur_pos should be updated to point to that payload.
	 *
	 * @param packet The packet to analyze.
	 *
	 * @return A tuple of analysis result and identifier. The result indicates
	 * how to proceed. If analysis can continue, the identifier determines the
	 * encapsulated protocol.
	 */
	virtual std::tuple<AnalyzerResult, identifier_t> analyze(Packet *packet) = 0;

protected:
	friend class Manager;

private:
    Tag tag;

    void init(const Tag& tag);
};

} // llanalyzer namespace end