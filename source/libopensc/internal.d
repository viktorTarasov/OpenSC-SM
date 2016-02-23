// D import file generated from 'internal.d' renamed to 'internal.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// No function exported from "libopensc.*"

module libopensc.internal;
import core.stdc.config : c_ulong;
import scconf.scconf;
extern (C) 
{
	enum SC_FILE_MAGIC = 339896656;
	struct sc_atr_table
	{
		immutable(char)* atr;
		immutable(char)* atrmask;
		immutable(char)* name;
		int type;
		c_ulong flags;
		scconf_block* card_atr;
	}
}
