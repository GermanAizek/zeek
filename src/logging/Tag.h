// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"
#include "zeek/Tag.h"

namespace zeek::logging
	{

/**
 * Class to identify a writer type.
 *
 * The script-layer analogue is Log::Writer.
 */
class Tag : public zeek::Tag
	{
public:
	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag() : zeek::Tag() { }

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a logging::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to an writer for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Log::Writer.
	 */
	explicit Tag(EnumValPtr val);

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal writer type.
	 */
	explicit operator bool() const { return *this != Error; }

	/**
	 * Returns the \c Log::Writer enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	const EnumValPtr& AsVal() const;

	static const Tag Error;
	};

	} // namespace zeek::logging
