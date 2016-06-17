// No function exported from "libopensc.*"

module libopensc.internal;

import core.stdc.config : c_ulong;
import scconf.scconf : scconf_block;

extern (C) 
{
	enum SC_FILE_MAGIC = 0x1442_6950;

	struct sc_atr_table
	{
		const(char)* atr;
		const(char)* atrmask;
		const(char)* name;
		int type;
		c_ulong flags;
		scconf_block* card_atr;
	}
}
