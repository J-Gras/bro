#ifndef PREFIXTABLE_H
#define PREFIXTABLE_H

#include "Val.h"
#include "net_util.h"
#include "IPAddr.h"

extern "C" {
	#include "patricia.h"
}

class PrefixTable {
private:
	patricia_tree_t* tree;

public:
	struct iterator {
	private:
		patricia_node_t* Xstack[PATRICIA_MAXBITS+1];
		patricia_node_t** Xsp;
		patricia_node_t* Xrn;
		patricia_node_t* Xnode;
		int Xstack_size;
		int cnt;
	friend PrefixTable;
	};

	PrefixTable()	{ tree = New_Patricia(128); }
	~PrefixTable()	{ Destroy_Patricia(tree, 0); }

	// Addr in network byte order. If data is zero, acts like a set.
	// Returns ptr to old data if already existing.
	// For existing items without data, returns non-nil if found.
	void* Insert(const IPAddr& addr, int width, void* data = 0);

	// Value may be addr or subnet.
	void* Insert(const Val* value, void* data = 0);

	// Returns nil if not found, pointer to data otherwise.
	// For items without data, returns non-nil if found.
	// If exact is false, performs exact rather than longest-prefix match.
	void* Lookup(const IPAddr& addr, int width, bool exact = false) const;
	void* Lookup(const Val* value, bool exact = false) const;

	// Returns an iterator that can be used to lookup all prefixes
	// that contain the given prefix.
	iterator* InitLookupAll(const IPAddr& addr, int width) const;
	iterator* InitLookupAll(const Val* value) const;
	// Returns true as long as the call retrieved a valid item.
	bool NextLookupAll(iterator* i, Val* &value, void* &data) const;

	// Returns pointer to data or nil if not found.
	void* Remove(const IPAddr& addr, int width);
	void* Remove(const Val* value);

	void Clear()	{ Clear_Patricia(tree, 0); }

	iterator InitIterator();
	void* GetNext(iterator* i);
};

#endif
