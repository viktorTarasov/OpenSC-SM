// D import file generated from 'types.d' renamed to 'types.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions exported from "libopensc.*"

module libopensc.types;
import core.stdc.config : c_ulong;
template FreeEnumMembers(T) if (is(T == enum))
{
	mixin(()
	{
		string s;
		foreach (member; __traits(allMembers, T))
		{
			s ~= "enum T " ~ member ~ " = T." ~ member ~ ";\x0a";
		}
		return s;
	}
	());
}
extern (C) 
{
	alias SC_MAX_t = int;
	enum : SC_MAX_t
	{
		SC_MAX_CARD_DRIVERS = 48,
		SC_MAX_CARD_DRIVER_SNAME_SIZE = 16,
		SC_MAX_CARD_APPS = 8,
		SC_MAX_APDU_BUFFER_SIZE = 261,
		SC_MAX_EXT_APDU_BUFFER_SIZE = 65538,
		SC_MAX_PIN_SIZE = 256,
		SC_MAX_ATR_SIZE = 33,
		SC_MAX_AID_SIZE = 16,
		SC_MAX_AID_STRING_SIZE = SC_MAX_AID_SIZE * 2 + 3,
		SC_MAX_IIN_SIZE = 10,
		SC_MAX_OBJECT_ID_OCTETS = 16,
		SC_MAX_PATH_SIZE = 16,
		SC_MAX_PATH_STRING_SIZE = SC_MAX_PATH_SIZE * 2 + 3,
		SC_MAX_SDO_ACLS = 8,
		SC_MAX_CRTS_IN_SE = 12,
		SC_MAX_SE_NUM = 8,
		SC_MAX_SUPPORTED_ALGORITHMS = 8,
	}
	struct sc_lv_data
	{
		ubyte* value;
		size_t len;
	}
	struct sc_tlv_data
	{
		uint tag;
		ubyte* value;
		size_t len;
	}
	struct sc_object_id
	{
		int[SC_MAX_OBJECT_ID_OCTETS] value;
	}
	struct sc_aid
	{
		ubyte[SC_MAX_AID_SIZE] value;
		size_t len;
	}
	struct sc_atr
	{
		ubyte[SC_MAX_ATR_SIZE] value;
		size_t len;
	}
	struct sc_iid
	{
		ubyte[SC_MAX_IIN_SIZE] value;
		size_t len;
	}
	struct sc_version
	{
		ubyte hw_major;
		ubyte hw_minor;
		ubyte fw_major;
		ubyte fw_minor;
	}
	struct sc_ddo
	{
		sc_aid aid;
		sc_iid iid;
		sc_object_id oid;
		size_t len;
		ubyte* value;
	}

	enum SC_PATH_TYPE 
	{
		SC_PATH_TYPE_FILE_ID = 0,
		SC_PATH_TYPE_DF_NAME = 1,
		SC_PATH_TYPE_PATH = 2,
		SC_PATH_TYPE_PATH_PROT = 3,
		SC_PATH_TYPE_FROM_CURRENT = 4,
		SC_PATH_TYPE_PARENT = 5,
	}
	mixin FreeEnumMembers!SC_PATH_TYPE;

	struct sc_path
	{
		ubyte[SC_MAX_PATH_SIZE] value;
		size_t len;
		int index;
		int count;
		int type;
		sc_aid aid;
	}
	struct sc_crt
	{
		uint tag;
		uint usage;
		uint algo;
		uint[8] refs;
	}

	enum SC_AC : uint
	{
		SC_AC_NONE = uint.min,
		SC_AC_CHV = 1,
		SC_AC_TERM = 2,
		SC_AC_PRO = 4,
		SC_AC_AUT = 8,
		SC_AC_SYMBOLIC = 16,
		SC_AC_SEN = 32,
		SC_AC_SCB = 64,
		SC_AC_IDA = 128,
		SC_AC_UNKNOWN = uint.max-1,
		SC_AC_NEVER   = uint.max,
	}
	mixin FreeEnumMembers!SC_AC;

	enum 
	{
		SC_AC_OP_SELECT = 0,
		SC_AC_OP_LOCK = 1,
		SC_AC_OP_DELETE = 2,
		SC_AC_OP_CREATE = 3,
		SC_AC_OP_REHABILITATE = 4,
		SC_AC_OP_INVALIDATE = 5,
		SC_AC_OP_LIST_FILES = 6,
		SC_AC_OP_CRYPTO = 7,
		SC_AC_OP_DELETE_SELF = 8,
		SC_AC_OP_PSO_DECRYPT = 9,
		SC_AC_OP_PSO_ENCRYPT = 10,
		SC_AC_OP_PSO_COMPUTE_SIGNATURE = 11,
		SC_AC_OP_PSO_VERIFY_SIGNATURE = 12,
		SC_AC_OP_PSO_COMPUTE_CHECKSUM = 13,
		SC_AC_OP_PSO_VERIFY_CHECKSUM = 14,
		SC_AC_OP_INTERNAL_AUTHENTICATE = 15,
		SC_AC_OP_EXTERNAL_AUTHENTICATE = 16,
		SC_AC_OP_PIN_DEFINE = 17,
		SC_AC_OP_PIN_CHANGE = 18,
		SC_AC_OP_PIN_RESET = 19,
		SC_AC_OP_ACTIVATE = 20,
		SC_AC_OP_DEACTIVATE = 21,
		SC_AC_OP_READ = 22,
		SC_AC_OP_UPDATE = 23,
		SC_AC_OP_WRITE = 24,
		SC_AC_OP_RESIZE = 25,
		SC_AC_OP_GENERATE = 26,
		SC_AC_OP_CREATE_EF = 27,
		SC_AC_OP_CREATE_DF = 28,
		SC_AC_OP_ADMIN = 29,
		SC_AC_OP_PIN_USE = 30,
		SC_MAX_AC_OPS = 31,
		SC_AC_OP_ERASE = SC_AC_OP_DELETE,
	}

	enum SC_AC_KEY_REF_NONE = uint.max;

	struct sc_acl_entry
	{
		uint method;
		uint key_ref;
		sc_crt[SC_MAX_CRTS_IN_SE] crts;
		sc_acl_entry* next;
	}

	enum SC_FILE_TYPE
	{
		SC_FILE_TYPE_DF = 4,
		SC_FILE_TYPE_INTERNAL_EF = 3,
//	SC_FILE_TYPE_INTERNAL_SE_EF = 7,
		SC_FILE_TYPE_WORKING_EF = 1,
		SC_FILE_TYPE_BSO = 16, // BSO (Base Security Object) BSO contains data that must never go out from the card, but are essential for cryptographic operations, like PINs or Private Keys
	}
	mixin FreeEnumMembers!SC_FILE_TYPE;
	
	enum 
	{
		SC_FILE_EF_UNKNOWN = 0,
		SC_FILE_EF_TRANSPARENT = 1,
		SC_FILE_EF_LINEAR_FIXED = 2,
		SC_FILE_EF_LINEAR_FIXED_TLV = 3,
		SC_FILE_EF_LINEAR_VARIABLE = 4,
		SC_FILE_EF_LINEAR_VARIABLE_TLV = 5,
		SC_FILE_EF_CYCLIC = 6,
		SC_FILE_EF_CYCLIC_TLV = 7,
	}
	enum 
	{
		SC_FILE_STATUS_ACTIVATED = 0,
		SC_FILE_STATUS_INVALIDATED = 1,
		SC_FILE_STATUS_CREATION = 2,
	}
	struct sc_file
	{
		sc_path path;
		ubyte[16] name;
		size_t namelen;
		uint type;
		uint ef_structure;
		uint status;
		uint shareable;
		size_t size;
		int id;
		int sid;
		sc_acl_entry[SC_MAX_AC_OPS]* acl;
		int record_length;
		int record_count;
		ubyte* sec_attr;
		size_t sec_attr_len;
		ubyte* prop_attr;
		size_t prop_attr_len;
		ubyte* type_attr;
		size_t type_attr_len;
		ubyte* encoded_content;
		size_t encoded_content_len;
		uint magic;
	}
	enum 
	{
		SC_APDU_CASE_NONE = 0,
		SC_APDU_CASE_1 = 1,
		SC_APDU_CASE_2_SHORT = 2,
		SC_APDU_CASE_3_SHORT = 3,
		SC_APDU_CASE_4_SHORT = 4,
		SC_APDU_SHORT_MASK = 15,
		SC_APDU_EXT = 16,
		SC_APDU_CASE_2_EXT = SC_APDU_CASE_2_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_3_EXT = SC_APDU_CASE_3_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_4_EXT = SC_APDU_CASE_4_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_2 = 34,
		SC_APDU_CASE_3 = 35,
		SC_APDU_CASE_4 = 36,
	}
	enum : uint
	{
		SC_APDU_FLAGS_CHAINING = 1LU,
		SC_APDU_FLAGS_NO_GET_RESP = 2LU,
		SC_APDU_FLAGS_NO_RETRY_WL = 4LU,
	}
	enum 
	{
		SC_APDU_ALLOCATE_FLAG = 1,
		SC_APDU_ALLOCATE_FLAG_DATA = 2,
		SC_APDU_ALLOCATE_FLAG_RESP = 4,
	}
	struct sc_apdu
	{
		int cse;
		ubyte cla;
		ubyte ins;
		ubyte p1;
		ubyte p2;
		size_t lc;
		size_t le;
		const(ubyte)* data;
		size_t datalen;
		ubyte* resp;
		size_t resplen;
		ubyte control;
		uint allocation_flags;
		uint sw1;
		uint sw2;
		ubyte[8] mac;
		size_t mac_len;
		c_ulong flags;
		sc_apdu* next;
	}
	enum 
	{
		SC_CPLC_TAG = 40831,
		SC_CPLC_DER_SIZE = 45,
	}
	struct sc_cplc
	{
		ubyte[2] ic_fabricator;
		ubyte[2] ic_type;
		ubyte[6] os_data;
		ubyte[2] ic_date;
		ubyte[4] ic_serial;
		ubyte[2] ic_batch_id;
		ubyte[4] ic_module_data;
		ubyte[2] icc_manufacturer;
		ubyte[2] ic_embed_date;
		ubyte[6] pre_perso_data;
		ubyte[6] personalizer_data;
		ubyte[SC_CPLC_DER_SIZE] value;
		size_t len;
	}
	struct sc_iin
	{
		ubyte mii;
		uint country;
		c_ulong issuer_id;
	}
	enum SC_MAX_SERIALNR = 32;
	struct sc_serial_number
	{
		ubyte[SC_MAX_SERIALNR] value;
		size_t len;
		sc_iin iin;
	}
	enum 
	{
		SC_REMOTE_APDU_FLAG_NOT_FATAL = 1,
		SC_REMOTE_APDU_FLAG_RETURN_ANSWER = 2,
	}
	struct sc_remote_apdu
	{
		ubyte[2 * SC_MAX_APDU_BUFFER_SIZE] sbuf;
		ubyte[2 * SC_MAX_APDU_BUFFER_SIZE] rbuf;
		sc_apdu apdu;
		uint flags;
		sc_remote_apdu* next;
	}
	struct sc_remote_data
	{
		sc_remote_apdu* data;
		int length;
		int function(sc_remote_data* rdata, sc_remote_apdu** out_) alloc;
		void function(sc_remote_data* rdata) free;
	}
}
