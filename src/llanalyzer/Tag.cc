// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

llanalyzer::Tag llanalyzer::Tag::Error;

llanalyzer::Tag::Tag(type_t type, subtype_t subtype)
  : ::Tag(llanalyzer_mgr->GetTagType(), type, subtype) {
}

llanalyzer::Tag &llanalyzer::Tag::operator=(const llanalyzer::Tag &other) {
    ::Tag::operator=(other);
    return *this;
}

const IntrusivePtr<EnumVal>& llanalyzer::Tag::AsVal() const {
  return ::Tag::AsVal(llanalyzer_mgr->GetTagType());
}

EnumVal* llanalyzer::Tag::AsEnumVal() const {
  return AsVal().get();
}

llanalyzer::Tag::Tag(IntrusivePtr<EnumVal> val)
	: ::Tag(std::move(val))
	{ }

llanalyzer::Tag::Tag(EnumVal* val)
	: ::Tag({NewRef{}, val})
	{ }
