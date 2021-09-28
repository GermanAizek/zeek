#include "zeek/plugin/TaggedComponent.h"

namespace zeek::plugin {

Tag::type_t TaggedComponent::type_counter(0);

TaggedComponent::TaggedComponent(Tag::subtype_t subtype)
	: tag(1, 0), subtype(subtype), initialized(false)
	{
	}

/**
 * Initializes tag by creating the unique tag value for thos componend.
 * Has to be called exactly once.
 */
void TaggedComponent::InitializeTag()
	{
	assert(initialized == false);
	initialized = true;
	tag = zeek::Tag(++type_counter, subtype);
	}

/**
 * @return The component's tag.
 */
zeek::Tag TaggedComponent::Tag() const
	{
	assert(initialized);
	return tag;
	}

} // namespace zeek::plugin
