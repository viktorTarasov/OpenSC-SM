// Functions exported from "libopensc.*"

module libopensc.asn1;

import libopensc.opensc;
import libopensc.pkcs15;
import libopensc.types;
	
extern (C)
{
	struct sc_asn1_entry
	{
		const(char)* name;
		uint type;
		uint tag;
		uint flags;
		void* parm;
		void* arg;
	}

	struct sc_asn1_pkcs15_object
	{
		sc_pkcs15_object* p15_obj;
		sc_asn1_entry* asn1_class_attr;
		sc_asn1_entry* asn1_subclass_attr;
		sc_asn1_entry* asn1_type_attr;
	}

	struct sc_asn1_pkcs15_algorithm_info
	{
		int id;
		sc_object_id oid;
		int function(sc_context*, void**, const(ubyte)*, size_t, int) decode;
		int function(sc_context*, void*, ubyte**, size_t*, int) encode;
		void function(void*) free;
	}

	void sc_format_asn1_entry(sc_asn1_entry* entry, void* parm, void* arg, int set_present);
	void sc_copy_asn1_entry(const(sc_asn1_entry)* src, sc_asn1_entry* dest);
	int sc_asn1_decode(sc_context* ctx, sc_asn1_entry* asn1, const(ubyte)* in_, size_t len, const(ubyte)** newp, size_t* left);
	int sc_asn1_decode_choice(sc_context* ctx, sc_asn1_entry* asn1, const(ubyte)* in_, size_t len, const(ubyte)** newp, size_t* left);
	int sc_asn1_encode(sc_context* ctx, const(sc_asn1_entry)* asn1, ubyte** buf, size_t* bufsize);
	int _sc_asn1_decode(sc_context*, sc_asn1_entry*, const(ubyte)*, size_t, const(ubyte)**, size_t*, int, int);
	int _sc_asn1_encode(sc_context*, const(sc_asn1_entry)*, ubyte**, size_t*, int);
	int sc_asn1_read_tag(const(ubyte)** buf, size_t buflen, uint* cla_out, uint* tag_out, size_t* taglen);
	const(ubyte)* sc_asn1_find_tag(sc_context* ctx, const(ubyte)* buf, size_t buflen, uint tag, size_t* taglen);
	const(ubyte)* sc_asn1_verify_tag(sc_context* ctx, const(ubyte)* buf, size_t buflen, uint tag, size_t* taglen);
	const(ubyte)* sc_asn1_skip_tag(sc_context* ctx, const(ubyte)** buf, size_t* buflen, uint tag, size_t* taglen);
	int sc_asn1_put_tag(uint tag, const(ubyte)* data, size_t datalen, ubyte* out_, size_t outlen, ubyte** ptr);
	void sc_asn1_print_tags(const(ubyte)* buf, size_t buflen);
	int sc_asn1_utf8string_to_ascii(const(ubyte)* buf, size_t buflen, ubyte* outbuf, size_t outlen);
	int sc_asn1_decode_bit_string(const(ubyte)* inbuf, size_t inlen, void* outbuf, size_t outlen);
	int sc_asn1_decode_bit_string_ni(const(ubyte)* inbuf, size_t inlen, void* outbuf, size_t outlen);
	int sc_asn1_decode_integer(const(ubyte)* inbuf, size_t inlen, int* out_);
	int sc_asn1_decode_object_id(const(ubyte)* inbuf, size_t inlen, sc_object_id* id);
	int sc_asn1_encode_object_id(ubyte** buf, size_t* buflen, const(sc_object_id)* id);
	int sc_asn1_decode_algorithm_id(sc_context*, const(ubyte)*, size_t, sc_algorithm_id*, int);
	int sc_asn1_encode_algorithm_id(sc_context*, ubyte**, size_t*, const(sc_algorithm_id)*, int);
	void sc_asn1_clear_algorithm_id(sc_algorithm_id*);
	int sc_asn1_write_element(sc_context* ctx, uint tag, const(ubyte)* data, size_t datalen, ubyte** out_, size_t* outlen);
	int sc_asn1_sig_value_rs_to_sequence(sc_context* ctx, ubyte* in_, size_t inlen, ubyte** buf, size_t* buflen);
	int sc_asn1_sig_value_sequence_to_rs(sc_context* ctx, ubyte* in_, size_t inlen, ubyte* buf, size_t buflen);

	enum 
	{
		SC_ASN1_CLASS_MASK      = 0x3000_0000,
		SC_ASN1_UNI             = 0x0000_0000, /* Universal */
		SC_ASN1_APP             = 0x1000_0000, /* Application */
		SC_ASN1_CTX             = 0x2000_0000, /* Context */
		SC_ASN1_PRV             = 0x3000_0000, /* Private */
		SC_ASN1_CONS            = 0x0100_0000,
		SC_ASN1_TAG_MASK        = 0x00FF_FFFF,
		SC_ASN1_TAGNUM_SIZE     = 3,
		SC_ASN1_PRESENT         = 1,
		SC_ASN1_OPTIONAL        = 2,
		SC_ASN1_ALLOC           = 4,
		SC_ASN1_UNSIGNED        = 8,
		SC_ASN1_EMPTY_ALLOWED   = 16,
		SC_ASN1_BOOLEAN         = 1,
		SC_ASN1_INTEGER         = 2,
		SC_ASN1_BIT_STRING      = 3,
		SC_ASN1_BIT_STRING_NI   = 128,
		SC_ASN1_OCTET_STRING    = 4,
		SC_ASN1_NULL            = 5,
		SC_ASN1_OBJECT          = 6,
		SC_ASN1_ENUMERATED      = 10,
		SC_ASN1_UTF8STRING      = 12,
		SC_ASN1_SEQUENCE        = 16,
		SC_ASN1_SET             = 17,
		SC_ASN1_PRINTABLESTRING = 19,
		SC_ASN1_UTCTIME         = 23,
		SC_ASN1_GENERALIZEDTIME = 24,
		SC_ASN1_STRUCT          = 129,
		SC_ASN1_CHOICE          = 130,
		SC_ASN1_BIT_FIELD       = 131,
		SC_ASN1_PATH            = 256,
		SC_ASN1_PKCS15_ID       = 257,
		SC_ASN1_PKCS15_OBJECT   = 258,
		SC_ASN1_ALGORITHM_ID    = 259,
		SC_ASN1_SE_INFO         = 260,
		SC_ASN1_CALLBACK        = 384,
	}

	enum 
	{
		SC_ASN1_TAG_CLASS             = 192,
		SC_ASN1_TAG_UNIVERSAL         = 0,
		SC_ASN1_TAG_APPLICATION       = 64,
		SC_ASN1_TAG_CONTEXT           = 128,
		SC_ASN1_TAG_PRIVATE           = 192,
		SC_ASN1_TAG_CONSTRUCTED       = 32,
		SC_ASN1_TAG_PRIMITIVE         = 31,
		SC_ASN1_TAG_EOC               = 0,
		SC_ASN1_TAG_BOOLEAN           = 1,
		SC_ASN1_TAG_INTEGER           = 2,
		SC_ASN1_TAG_BIT_STRING        = 3,
		SC_ASN1_TAG_OCTET_STRING      = 4,
		SC_ASN1_TAG_NULL              = 5,
		SC_ASN1_TAG_OBJECT            = 6,
		SC_ASN1_TAG_OBJECT_DESCRIPTOR = 7,
		SC_ASN1_TAG_EXTERNAL          = 8,
		SC_ASN1_TAG_REAL              = 9,
		SC_ASN1_TAG_ENUMERATED        = 10,
		SC_ASN1_TAG_UTF8STRING        = 12,
		SC_ASN1_TAG_SEQUENCE          = 16,
		SC_ASN1_TAG_SET               = 17,
		SC_ASN1_TAG_NUMERICSTRING     = 18,
		SC_ASN1_TAG_PRINTABLESTRING   = 19,
		SC_ASN1_TAG_T61STRING         = 20,
		SC_ASN1_TAG_TELETEXSTRING     = 20,
		SC_ASN1_TAG_VIDEOTEXSTRING    = 21,
		SC_ASN1_TAG_IA5STRING         = 22,
		SC_ASN1_TAG_UTCTIME           = 23,
		SC_ASN1_TAG_GENERALIZEDTIME   = 24,
		SC_ASN1_TAG_GRAPHICSTRING     = 25,
		SC_ASN1_TAG_ISO64STRING       = 26,
		SC_ASN1_TAG_VISIBLESTRING     = 26,
		SC_ASN1_TAG_GENERALSTRING     = 27,
		SC_ASN1_TAG_UNIVERSALSTRING   = 28,
		SC_ASN1_TAG_BMPSTRING         = 30,
		SC_ASN1_TAG_ESCAPE_MARKER     = 31,
	}
}
