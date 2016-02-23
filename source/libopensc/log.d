// D import file generated from 'log.d' renamed to 'log.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions exported from "libopensc.*"

module libopensc.log;
import std.string : toStringz;
import libopensc.types : sc_object_id;
import libopensc.opensc;
template ArgStringOf(TS...)
{
	static if (TS.length == 0)
	{
		enum ArgStringOf = "";
	}
	else
	{
		static if (TS.length == 1)
		{
			enum ArgStringOf = TS[0];
		}
		else
		{
			enum ArgStringOf = TS[0] ~ "," ~ ArgStringOf!(TS[1 .. $]);
		}
	}
}
enum log(PS...) = "sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, " ~ ArgStringOf!PS ~ ");";
extern (C) 
{
	alias SC_LOG_DEBUG_t = int;
	enum : SC_LOG_DEBUG_t
	{
		SC_LOG_DEBUG_VERBOSE_TOOL = 1,
		SC_LOG_DEBUG_VERBOSE,
		SC_LOG_DEBUG_NORMAL,
		SC_LOG_DEBUG_RFU1,
		SC_LOG_DEBUG_RFU2,
		SC_LOG_DEBUG_ASN1,
		SC_LOG_DEBUG_MATCH,
	}
	void sc_do_log(sc_context* ctx, int level, const(char)* file, int line, const(char)* func, const(char)* format, ...);
	void _sc_debug(sc_context* ctx, int level, const(char)* format, ...);
	void sc_hex_dump(sc_context* ctx, int level, const(ubyte)* buf, size_t len, char* out_, size_t outlen);
	char* sc_dump_hex(const(ubyte)* in_, size_t count);
}
