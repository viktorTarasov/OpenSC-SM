module libopensc.pkcs15;

import core.stdc.config : c_ulong;
import libopensc.opensc;
import libopensc.types;
import scconf.scconf;
import libopensc.auxdata;

version(FAKE_OPENSC_VERSION)
{
	version = UPTO_15_OPENSC_VERSION;
}

extern (C) 
{
	enum SC_PKCS15_CACHE_DIR = ".eid";
	enum SC_PKCS15_PIN_MAGIC = 826366246;
	enum SC_PKCS15_MAX_PINS = 8;
	enum SC_PKCS15_MAX_LABEL_SIZE = 255;
	enum SC_PKCS15_MAX_ID_SIZE = 255;
	enum SC_PKCS15_MAX_ACCESS_RULES = 8;
	struct sc_pkcs15_id
	{
		ubyte[SC_PKCS15_MAX_ID_SIZE] value;
		size_t len;
	}
	enum 
	{
		SC_PKCS15_CO_FLAG_PRIVATE = 1,
		SC_PKCS15_CO_FLAG_MODIFIABLE = 2,
		SC_PKCS15_CO_FLAG_OBJECT_SEEN = 2147483648u,
	}
	enum 
	{
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE = 1,
		SC_PKCS15_PIN_FLAG_LOCAL = 2,
		SC_PKCS15_PIN_FLAG_CHANGE_DISABLED = 4,
		SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED = 8,
		SC_PKCS15_PIN_FLAG_INITIALIZED = 16,
		SC_PKCS15_PIN_FLAG_NEEDS_PADDING = 32,
		SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN = 64,
		SC_PKCS15_PIN_FLAG_SO_PIN = 128,
		SC_PKCS15_PIN_FLAG_DISABLE_ALLOW = 256,
		SC_PKCS15_PIN_FLAG_INTEGRITY_PROTECTED = 512,
		SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED = 1024,
		SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA = 2048,
	}
	enum 
	{
		SC_PKCS15_PIN_TYPE_FLAGS_MASK = SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN,
		SC_PKCS15_PIN_TYPE_FLAGS_SOPIN = SC_PKCS15_PIN_FLAG_SO_PIN | SC_PKCS15_PIN_FLAG_INITIALIZED,
		SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL = SC_PKCS15_PIN_FLAG_INITIALIZED,
		SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
		SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL = SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_INITIALIZED,
		SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL = SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
	}
	enum 
	{
		SC_PKCS15_PIN_TYPE_BCD = 0,
		SC_PKCS15_PIN_TYPE_ASCII_NUMERIC = 1,
		SC_PKCS15_PIN_TYPE_UTF8 = 2,
		SC_PKCS15_PIN_TYPE_HALFNIBBLE_BCD = 3,
		SC_PKCS15_PIN_TYPE_ISO9564_1 = 4,
	}
	enum 
	{
		SC_PKCS15_PIN_AUTH_TYPE_PIN = 0,
		SC_PKCS15_PIN_AUTH_TYPE_BIOMETRIC = 1,
		SC_PKCS15_PIN_AUTH_TYPE_AUTH_KEY = 2,
		SC_PKCS15_PIN_AUTH_TYPE_SM_KEY = 3,
	}
	struct sc_pkcs15_pin_attributes
	{
		uint flags;
		uint type;
		size_t min_length;
		size_t stored_length;
		size_t max_length;
		int reference;
		ubyte pad_char;
	}
	struct sc_pkcs15_authkey_attributes
	{
		int derived;
		sc_pkcs15_id skey_id;
	}
	struct sc_pkcs15_biometric_attributes
	{
		uint flags;
		sc_object_id template_id;
	}
	struct sc_pkcs15_auth_info
	{
		sc_pkcs15_id auth_id;
		sc_path path;
		uint auth_type;
		union anonymous
		{
			sc_pkcs15_pin_attributes pin;
			sc_pkcs15_biometric_attributes bio;
			sc_pkcs15_authkey_attributes authkey;
		}
		anonymous attrs;
		uint auth_method;
		int tries_left;
		int max_tries;
		int max_unlocks;
	}
	enum 
	{
		SC_PKCS15_ALGO_OP_COMPUTE_CHECKSUM = 1,
		SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE = 2,
		SC_PKCS15_ALGO_OP_VERIFY_CHECKSUM = 4,
		SC_PKCS15_ALGO_OP_VERIFY_SIGNATURE = 8,
		SC_PKCS15_ALGO_OP_ENCIPHER = 16,
		SC_PKCS15_ALGO_OP_DECIPHER = 32,
		SC_PKCS15_ALGO_OP_HASH = 64,
		SC_PKCS15_ALGO_OP_GENERATE_KEY = 128,
	}
	struct sc_pkcs15_bignum
	{
		ubyte* data;
		size_t len;
	}
	struct sc_pkcs15_der
	{
		ubyte* value;
		size_t len;
	}
	struct sc_pkcs15_u8
	{
		ubyte* value;
		size_t len;
	}
	struct sc_pkcs15_pubkey_rsa
	{
		sc_pkcs15_bignum modulus;
		sc_pkcs15_bignum exponent;
	}
	struct sc_pkcs15_prkey_rsa
	{
		sc_pkcs15_bignum modulus;
		sc_pkcs15_bignum exponent;
		sc_pkcs15_bignum d;
		sc_pkcs15_bignum p;
		sc_pkcs15_bignum q;
		sc_pkcs15_bignum iqmp;
		sc_pkcs15_bignum dmp1;
		sc_pkcs15_bignum dmq1;
	}
	struct sc_pkcs15_pubkey_dsa
	{
		sc_pkcs15_bignum pub;
		sc_pkcs15_bignum p;
		sc_pkcs15_bignum q;
		sc_pkcs15_bignum g;
	}
	struct sc_pkcs15_prkey_dsa
	{
		sc_pkcs15_bignum pub;
		sc_pkcs15_bignum p;
		sc_pkcs15_bignum q;
		sc_pkcs15_bignum g;
		sc_pkcs15_bignum priv;
	}
	struct sc_pkcs15_gost_parameters
	{
		sc_object_id key;
		sc_object_id hash;
		sc_object_id cipher;
	}
	struct sc_pkcs15_pubkey_ec
	{
		sc_ec_parameters params;
		sc_pkcs15_u8 ecpointQ;
	}
	struct sc_pkcs15_prkey_ec
	{
		sc_ec_parameters params;
		sc_pkcs15_bignum privateD;
		sc_pkcs15_u8 ecpointQ;
	}
	struct sc_pkcs15_pubkey_gostr3410
	{
		sc_pkcs15_gost_parameters params;
		sc_pkcs15_bignum xy;
	}
	struct sc_pkcs15_prkey_gostr3410
	{
		sc_pkcs15_gost_parameters params;
		sc_pkcs15_bignum d;
	}
	struct sc_pkcs15_pubkey
	{
		int algorithm;
		sc_algorithm_id* alg_id;
		union anonymous
		{
			sc_pkcs15_pubkey_rsa rsa;
			sc_pkcs15_pubkey_dsa dsa;
			sc_pkcs15_pubkey_ec ec;
			sc_pkcs15_pubkey_gostr3410 gostr3410;
		}
		anonymous u;
	}
	struct sc_pkcs15_prkey
	{
		uint algorithm;
		union anonymous
		{
			sc_pkcs15_prkey_rsa rsa;
			sc_pkcs15_prkey_dsa dsa;
			sc_pkcs15_prkey_ec ec;
			sc_pkcs15_prkey_gostr3410 gostr3410;
		}
		anonymous u;
	}
	struct sc_pkcs15_enveloped_data
	{
		sc_pkcs15_id id;
		sc_algorithm_id ke_alg;
		ubyte* key;
		size_t key_len;
		sc_algorithm_id ce_alg;
		ubyte* content;
		size_t content_len;
	}
	struct sc_pkcs15_cert
	{
		int version_;
		ubyte* serial;
		size_t serial_len;
		ubyte* issuer;
		size_t issuer_len;
		ubyte* subject;
		size_t subject_len;
		ubyte* crl;
		size_t crl_len;
		sc_pkcs15_pubkey* key;
		sc_pkcs15_der data;
	}
	struct sc_pkcs15_cert_info
	{
		sc_pkcs15_id id;
		int authority;
		sc_path path;
		sc_pkcs15_der value;
	}
	struct sc_pkcs15_data
	{
		ubyte* data;
		size_t data_len;
	}
	struct sc_pkcs15_data_info
	{
		sc_pkcs15_id id;
		char[SC_PKCS15_MAX_LABEL_SIZE] app_label;
		sc_object_id app_oid;
		sc_path path;
		sc_pkcs15_der data;
	}
	enum 
	{
		SC_PKCS15_PRKEY_USAGE_ENCRYPT = 1,
		SC_PKCS15_PRKEY_USAGE_DECRYPT = 2,
		SC_PKCS15_PRKEY_USAGE_SIGN = 4,
		SC_PKCS15_PRKEY_USAGE_SIGNRECOVER = 8,
		SC_PKCS15_PRKEY_USAGE_WRAP = 16,
		SC_PKCS15_PRKEY_USAGE_UNWRAP = 32,
		SC_PKCS15_PRKEY_USAGE_VERIFY = 64,
		SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER = 128,
		SC_PKCS15_PRKEY_USAGE_DERIVE = 256,
		SC_PKCS15_PRKEY_USAGE_NONREPUDIATION = 512,
	}
	enum 
	{
		SC_PKCS15_PRKEY_ACCESS_SENSITIVE = 1,
		SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE = 2,
		SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE = 4,
		SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE = 8,
		SC_PKCS15_PRKEY_ACCESS_LOCAL = 16,
	}
	enum 
	{
		SC_PKCS15_PARAMSET_GOSTR3410_A = 1,
		SC_PKCS15_PARAMSET_GOSTR3410_B = 2,
		SC_PKCS15_PARAMSET_GOSTR3410_C = 3,
	}
	enum SC_PKCS15_GOSTR3410_KEYSIZE = 256;
	struct sc_pkcs15_keyinfo_gostparams
	{
		uint gostr3410;
		uint gostr3411;
		uint gost28147;
	}
	enum 
	{
		SC_PKCS15_ACCESS_RULE_MODE_READ = 1,
		SC_PKCS15_ACCESS_RULE_MODE_UPDATE = 2,
		SC_PKCS15_ACCESS_RULE_MODE_EXECUTE = 4,
		SC_PKCS15_ACCESS_RULE_MODE_DELETE = 8,
		SC_PKCS15_ACCESS_RULE_MODE_ATTRIBUTE = 16,
		SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS = 32,
		SC_PKCS15_ACCESS_RULE_MODE_PSO_VERIFY = 64,
		SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT = 128,
		SC_PKCS15_ACCESS_RULE_MODE_PSO_ENCRYPT = 256,
		SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH = 512,
		SC_PKCS15_ACCESS_RULE_MODE_EXT_AUTH = 1024,
	}
	struct sc_pkcs15_accessrule
	{
		uint access_mode;
		sc_pkcs15_id auth_id;
	}
	struct sc_pkcs15_key_params
	{
		void* data;
		size_t len;
		void function(void*) free_params;
	}
	
version(UPTO_15_OPENSC_VERSION)
{
	enum SC_MD_MAX_CONTAINER_NAME_LEN = 39;
	enum SC_MD_CONTAINER_MAP_VALID_CONTAINER = 1;
	enum SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER = 2;
	struct sc_md_cmap_record
	{
		ubyte* guid;
		size_t guid_len;
		uint flags;
		uint keysize_sign;
		uint keysize_keyexchange;
	}
	struct sc_md_cardcf
	{
		ubyte version_;
		ubyte pin_freshness;
		uint cont_freshness;
		uint files_freshness;
	}
	struct sc_md_data
	{
		sc_md_cardcf cardcf;
		void* prop_data;
	}
}
else
{
	struct sc_md_data;
}

	struct sc_pkcs15_prkey_info
	{
		sc_pkcs15_id id;
		uint usage;
		uint access_flags;
		int native;
		int key_reference;
		size_t modulus_length;
		size_t field_length;
		uint[SC_MAX_SUPPORTED_ALGORITHMS] algo_refs;
		sc_pkcs15_der subject;
		sc_pkcs15_key_params params;
		sc_path path;
version(UPTO_15_OPENSC_VERSION)
{
		sc_md_cmap_record cmap_record;
}
else
{
		sc_auxiliary_data* aux_data;
}
	}
//	alias sc_pkcs15_prkey_info_t = sc_pkcs15_prkey_info;
	
	struct sc_pkcs15_pubkey_info
	{
		sc_pkcs15_id id;
		uint usage;
		uint access_flags;
		int native;
		int key_reference;
		size_t modulus_length;
		size_t field_length;
		uint[SC_MAX_SUPPORTED_ALGORITHMS] algo_refs;
		sc_pkcs15_der subject;
		sc_pkcs15_key_params params;
		sc_path path;
		struct anonymous
		{
			sc_pkcs15_der raw;
			sc_pkcs15_der spki;
		}
		anonymous direct;
	}
	struct sc_pkcs15_skey_info
	{
		sc_pkcs15_id id;
		uint usage;
		uint access_flags;
		int native;
		int key_reference;
		size_t value_len;
		c_ulong key_type;
		int[SC_MAX_SUPPORTED_ALGORITHMS] algo_refs;
		sc_path path;
		sc_pkcs15_der data;
	}
	alias sc_pkcs15_skey = sc_pkcs15_data;
	enum 
	{
		SC_PKCS15_TYPE_CLASS_MASK = 3840,
		SC_PKCS15_TYPE_PRKEY = 256,
		SC_PKCS15_TYPE_PRKEY_RSA = 257,
		SC_PKCS15_TYPE_PRKEY_DSA = 258,
		SC_PKCS15_TYPE_PRKEY_GOSTR3410 = 259,
		SC_PKCS15_TYPE_PRKEY_EC = 260,
		SC_PKCS15_TYPE_PUBKEY = 512,
		SC_PKCS15_TYPE_PUBKEY_RSA = 513,
		SC_PKCS15_TYPE_PUBKEY_DSA = 514,
		SC_PKCS15_TYPE_PUBKEY_GOSTR3410 = 515,
		SC_PKCS15_TYPE_PUBKEY_EC = 516,
		SC_PKCS15_TYPE_SKEY = 768,
		SC_PKCS15_TYPE_SKEY_GENERIC = 769,
		SC_PKCS15_TYPE_SKEY_DES = 770,
		SC_PKCS15_TYPE_SKEY_2DES = 771,
		SC_PKCS15_TYPE_SKEY_3DES = 772,
		SC_PKCS15_TYPE_CERT = 1024,
		SC_PKCS15_TYPE_CERT_X509 = 1025,
		SC_PKCS15_TYPE_CERT_SPKI = 1026,
		SC_PKCS15_TYPE_DATA_OBJECT = 1280,
		SC_PKCS15_TYPE_AUTH = 1536,
		SC_PKCS15_TYPE_AUTH_PIN = 1537,
		SC_PKCS15_TYPE_AUTH_BIO = 1538,
		SC_PKCS15_TYPE_AUTH_AUTHKEY = 1539,
	}
	enum 
	{
		SC_PKCS15_SEARCH_CLASS_PRKEY = 2u,
		SC_PKCS15_SEARCH_CLASS_PUBKEY = 4u,
		SC_PKCS15_SEARCH_CLASS_SKEY = 8u,
		SC_PKCS15_SEARCH_CLASS_CERT = 16u,
		SC_PKCS15_SEARCH_CLASS_DATA = 32u,
		SC_PKCS15_SEARCH_CLASS_AUTH = 64u,
	}
	struct sc_pkcs15_object
	{
		uint type;
		char[SC_PKCS15_MAX_LABEL_SIZE] label;
		uint flags;
		sc_pkcs15_id auth_id;
		int usage_counter;
		int user_consent;
		sc_pkcs15_accessrule[SC_PKCS15_MAX_ACCESS_RULES] access_rules;
		void* data;
		void* emulated;
		sc_pkcs15_df* df;
		sc_pkcs15_object* next;
		sc_pkcs15_object* prev;
		sc_pkcs15_der content;
	}
	enum 
	{
		SC_PKCS15_PRKDF = 0,
		SC_PKCS15_PUKDF = 1,
		SC_PKCS15_PUKDF_TRUSTED = 2,
		SC_PKCS15_SKDF = 3,
		SC_PKCS15_CDF = 4,
		SC_PKCS15_CDF_TRUSTED = 5,
		SC_PKCS15_CDF_USEFUL = 6,
		SC_PKCS15_DODF = 7,
		SC_PKCS15_AODF = 8,
		SC_PKCS15_DF_TYPE_COUNT = 9,
	}
	struct sc_pkcs15_df
	{
		sc_path path;
		int record_length;
		uint type;
		int enumerated;
		sc_pkcs15_df* next;
		sc_pkcs15_df* prev;
	}
	struct sc_pkcs15_unusedspace
	{
		sc_path path;
		sc_pkcs15_id auth_id;
		sc_pkcs15_unusedspace* next;
		sc_pkcs15_unusedspace* prev;
	}
	enum SC_PKCS15_CARD_MAGIC = 270544960;
	struct sc_pkcs15_sec_env_info
	{
		int se;
		sc_object_id owner;
		sc_aid aid;
	}
	struct sc_pkcs15_last_update
	{
		char* gtime;
		sc_path path;
	}
	struct sc_pkcs15_profile_indication
	{
		sc_object_id oid;
		char* name;
	}
	struct sc_pkcs15_tokeninfo
	{
		uint version_;
		uint flags;
		char* label;
		char* serial_number;
		char* manufacturer_id;
		sc_pkcs15_last_update last_update;
		sc_pkcs15_profile_indication profile_indication;
		char* preferred_language;
		sc_pkcs15_sec_env_info** seInfo;
		size_t num_seInfo;
		sc_supported_algo_info[SC_MAX_SUPPORTED_ALGORITHMS] supported_algos;
	}
	struct sc_pkcs15_operations
	{
		int function(sc_pkcs15_card*, sc_pkcs15_df*) parse_df;
		void function(sc_pkcs15_card*) clear;
		int function(sc_pkcs15_card*, const(sc_pkcs15_object)*, ubyte*, size_t*) get_guid;
	}
	struct sc_pkcs15_card
	{
		sc_card* card;
		uint flags;
		sc_app_info* app;
		sc_file* file_app;
		sc_file* file_tokeninfo;
		sc_file* file_odf;
		sc_file* file_unusedspace;
		sc_pkcs15_df* df_list;
		sc_pkcs15_object* obj_list;
		sc_pkcs15_tokeninfo* tokeninfo;
		sc_pkcs15_unusedspace* unusedspace_list;
		int unusedspace_read;
		struct sc_pkcs15_card_opts
		{
			int use_file_cache;
			int use_pin_cache;
			int pin_cache_counter;
			int pin_cache_ignore_user_consent;
		}
		sc_pkcs15_card_opts opts;
		uint magic;
		void* dll_handle;
		sc_md_data* md_data;
		sc_pkcs15_operations ops;
	}
	enum 
	{
		SC_PKCS15_TOKEN_READONLY = 1,
		SC_PKCS15_TOKEN_LOGIN_REQUIRED = 2,
		SC_PKCS15_TOKEN_PRN_GENERATION = 4,
		SC_PKCS15_TOKEN_EID_COMPLIANT = 8,
	}
	enum SC_PKCS15_CARD_FLAG_EMULATED = 33554432;
	int sc_pkcs15_bind(sc_card* card, sc_aid* aid, sc_pkcs15_card** pkcs15_card);
	int sc_pkcs15_unbind(sc_pkcs15_card* card);
	int sc_pkcs15_bind_internal(sc_pkcs15_card* p15card, sc_aid* aid);
	int sc_pkcs15_get_objects(sc_pkcs15_card* card, uint type, sc_pkcs15_object** ret, size_t ret_count);
	int sc_pkcs15_get_objects_cond(sc_pkcs15_card* card, uint type, int function(sc_pkcs15_object*, void*) func, void* func_arg, sc_pkcs15_object** ret, size_t ret_count);
	int sc_pkcs15_find_object_by_id(sc_pkcs15_card*, uint, const(sc_pkcs15_id)*, sc_pkcs15_object**);
	sc_pkcs15_card* sc_pkcs15_card_new();
	void sc_pkcs15_card_free(sc_pkcs15_card* p15card);
	void sc_pkcs15_card_clear(sc_pkcs15_card* p15card);
	int sc_pkcs15_decipher(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong flags, const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen);
	int sc_pkcs15_derive(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong flags, const(ubyte)* in_, size_t inlen, ubyte* out_, c_ulong* poutlen);
	int sc_pkcs15_compute_signature(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong alg_flags, const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen);
	int sc_pkcs15_read_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, sc_pkcs15_pubkey**);
	int sc_pkcs15_decode_pubkey_rsa(sc_context*, sc_pkcs15_pubkey_rsa*, const(ubyte)*, size_t);
	int sc_pkcs15_encode_pubkey_rsa(sc_context*, sc_pkcs15_pubkey_rsa*, ubyte**, size_t*);
	int sc_pkcs15_decode_pubkey_dsa(sc_context*, sc_pkcs15_pubkey_dsa*, const(ubyte)*, size_t);
	int sc_pkcs15_encode_pubkey_dsa(sc_context*, sc_pkcs15_pubkey_dsa*, ubyte**, size_t*);
	int sc_pkcs15_decode_pubkey_gostr3410(sc_context*, sc_pkcs15_pubkey_gostr3410*, const(ubyte)*, size_t);
	int sc_pkcs15_encode_pubkey_gostr3410(sc_context*, sc_pkcs15_pubkey_gostr3410*, ubyte**, size_t*);
	int sc_pkcs15_decode_pubkey_ec(sc_context*, sc_pkcs15_pubkey_ec*, const(ubyte)*, size_t);
	int sc_pkcs15_encode_pubkey_ec(sc_context*, sc_pkcs15_pubkey_ec*, ubyte**, size_t*);
	int sc_pkcs15_decode_pubkey(sc_context*, sc_pkcs15_pubkey*, const(ubyte)*, size_t);
	int sc_pkcs15_encode_pubkey(sc_context*, sc_pkcs15_pubkey*, ubyte**, size_t*);
	int sc_pkcs15_encode_pubkey_as_spki(sc_context*, sc_pkcs15_pubkey*, ubyte**, size_t*);
	void sc_pkcs15_erase_pubkey(sc_pkcs15_pubkey*);
	void sc_pkcs15_free_pubkey(sc_pkcs15_pubkey*);
	int sc_pkcs15_pubkey_from_prvkey(sc_context*, sc_pkcs15_prkey*, sc_pkcs15_pubkey**);
	int sc_pkcs15_dup_pubkey(sc_context*, sc_pkcs15_pubkey*, sc_pkcs15_pubkey**);
	int sc_pkcs15_pubkey_from_cert(sc_context*, sc_pkcs15_der*, sc_pkcs15_pubkey**);
	int sc_pkcs15_pubkey_from_spki_file(sc_context*, char*, sc_pkcs15_pubkey**);
	int sc_pkcs15_pubkey_from_spki_fields(sc_context*, sc_pkcs15_pubkey**, ubyte*, size_t, int);
	int sc_pkcs15_encode_prkey(sc_context*, sc_pkcs15_prkey*, ubyte**, size_t*);
	void sc_pkcs15_free_prkey(sc_pkcs15_prkey* prkey);
	void sc_pkcs15_free_key_params(sc_pkcs15_key_params* params);
	int sc_pkcs15_read_data_object(sc_pkcs15_card* p15card, const(sc_pkcs15_data_info)* info, sc_pkcs15_data** data_object_out);
	int sc_pkcs15_find_data_object_by_id(sc_pkcs15_card* p15card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int sc_pkcs15_find_data_object_by_app_oid(sc_pkcs15_card* p15card, const(sc_object_id)* app_oid, sc_pkcs15_object** out_);
	int sc_pkcs15_find_data_object_by_name(sc_pkcs15_card* p15card, const(char)* app_label, const(char)* label, sc_pkcs15_object** out_);
	void sc_pkcs15_free_data_object(sc_pkcs15_data* data_object);
	int sc_pkcs15_read_certificate(sc_pkcs15_card* card, const(sc_pkcs15_cert_info)* info, sc_pkcs15_cert** cert);
	void sc_pkcs15_free_certificate(sc_pkcs15_cert* cert);
	int sc_pkcs15_find_cert_by_id(sc_pkcs15_card* card, const sc_pkcs15_id* id, sc_pkcs15_object** out_);
	int sc_pkcs15_create_cdf(sc_pkcs15_card* card, sc_file* file, const(sc_pkcs15_cert_info)** certs);
	int sc_pkcs15_create(sc_pkcs15_card* p15card, sc_card* card);
	int sc_pkcs15_find_prkey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int sc_pkcs15_find_prkey_by_id_usage(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, uint usage, sc_pkcs15_object** out_);
	int sc_pkcs15_find_prkey_by_reference(sc_pkcs15_card*, const(sc_path)*, int, sc_pkcs15_object**);
	int sc_pkcs15_find_pubkey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int sc_pkcs15_find_skey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int sc_pkcs15_verify_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* pincode, size_t pinlen);
	int sc_pkcs15_change_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* oldpincode, size_t oldpinlen, const(ubyte)* newpincode, size_t newpinlen);
	int sc_pkcs15_unblock_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* puk, size_t puklen, const(ubyte)* newpin, size_t newpinlen);
	int sc_pkcs15_find_pin_by_auth_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int sc_pkcs15_find_pin_by_reference(sc_pkcs15_card* card, const(sc_path)* path, int reference, sc_pkcs15_object** out_);
	int sc_pkcs15_find_pin_by_type_and_reference(sc_pkcs15_card* card, const(sc_path)* path, uint auth_method, int reference, sc_pkcs15_object** out_);
	int sc_pkcs15_find_so_pin(sc_pkcs15_card* card, sc_pkcs15_object** out_);
	int sc_pkcs15_find_pin_by_flags(sc_pkcs15_card* p15card, uint flags, uint mask, int* index, sc_pkcs15_object** out_);
	void sc_pkcs15_pincache_add(sc_pkcs15_card*, sc_pkcs15_object*, const(ubyte)*, size_t);
	int sc_pkcs15_pincache_revalidate(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* obj);
	void sc_pkcs15_pincache_clear(sc_pkcs15_card* p15card);
	int sc_pkcs15_encode_dir(sc_context* ctx, sc_pkcs15_card* card, ubyte** buf, size_t* buflen);
	int sc_pkcs15_parse_tokeninfo(sc_context* ctx, sc_pkcs15_tokeninfo* ti, const(ubyte)* buf, size_t blen);
	int sc_pkcs15_encode_tokeninfo(sc_context* ctx, sc_pkcs15_tokeninfo* ti, ubyte** buf, size_t* buflen);
	int sc_pkcs15_encode_odf(sc_context* ctx, sc_pkcs15_card* card, ubyte** buf, size_t* buflen);
	int sc_pkcs15_encode_df(sc_context* ctx, sc_pkcs15_card* p15card, sc_pkcs15_df* df, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_encode_cdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_encode_prkdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_encode_pukdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_encode_dodf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_encode_aodf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_parse_df(sc_pkcs15_card* p15card, sc_pkcs15_df* df);
	int sc_pkcs15_read_df(sc_pkcs15_card* p15card, sc_pkcs15_df* df);
	int sc_pkcs15_decode_cdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_dodf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_aodf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_prkdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_pukdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_skdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_enveloped_data(sc_context* ctx, sc_pkcs15_enveloped_data* result, const(ubyte)* buf, size_t buflen);
	int sc_pkcs15_encode_enveloped_data(sc_context* ctx, sc_pkcs15_enveloped_data* data, ubyte** buf, size_t* buflen);
	int sc_pkcs15_add_object(sc_pkcs15_card* p15card, sc_pkcs15_object* obj);
	void sc_pkcs15_remove_object(sc_pkcs15_card* p15card, sc_pkcs15_object* obj);
	int sc_pkcs15_add_df(sc_pkcs15_card*, uint, const(sc_path)*);
	int sc_pkcs15_add_unusedspace(sc_pkcs15_card* p15card, const(sc_path)* path, const(sc_pkcs15_id)* auth_id);
	int sc_pkcs15_parse_unusedspace(const(ubyte)* buf, size_t buflen, sc_pkcs15_card* card);
	int sc_pkcs15_encode_unusedspace(sc_context* ctx, sc_pkcs15_card* p15card, ubyte** buf, size_t* buflen);
	int sc_pkcs15_prkey_attrs_from_cert(sc_pkcs15_card*, sc_pkcs15_object*, sc_pkcs15_object**);
	void sc_pkcs15_free_prkey_info(sc_pkcs15_prkey_info* key);
	void sc_pkcs15_free_pubkey_info(sc_pkcs15_pubkey_info* key);
	void sc_pkcs15_free_cert_info(sc_pkcs15_cert_info* cert);
	void sc_pkcs15_free_data_info(sc_pkcs15_data_info* data);
	void sc_pkcs15_free_auth_info(sc_pkcs15_auth_info* auth_info);
	void sc_pkcs15_free_object(sc_pkcs15_object* obj);
	int sc_pkcs15_read_file(sc_pkcs15_card* p15card, const(sc_path)* path, ubyte** buf, size_t* buflen);
	int sc_pkcs15_read_cached_file(sc_pkcs15_card* p15card, const(sc_path)* path, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_cache_file(sc_pkcs15_card* p15card, const(sc_path)* path, const(ubyte)* buf, size_t bufsize);
	int sc_pkcs15_compare_id(const(sc_pkcs15_id)* id1, const(sc_pkcs15_id)* id2);
	const(char)* sc_pkcs15_print_id(const(sc_pkcs15_id)* id);
	void sc_pkcs15_format_id(const(char)* id_in, sc_pkcs15_id* id_out);
	int sc_pkcs15_hex_string_to_id(const(char)* in_, sc_pkcs15_id* out_);
	int sc_der_copy(sc_pkcs15_der*, const(sc_pkcs15_der)*);
	int sc_pkcs15_get_object_id(const(sc_pkcs15_object)*, sc_pkcs15_id*);
	int sc_pkcs15_get_object_guid(sc_pkcs15_card*, const(sc_pkcs15_object)*, uint, ubyte*, size_t*);
	int sc_pkcs15_serialize_guid(ubyte*, size_t, uint, char*, size_t);
	int sc_encode_oid(sc_context*, sc_object_id*, ubyte**, size_t*);
	sc_app_info* sc_pkcs15_get_application_by_type(sc_card*, char*);
	int sc_pkcs15_make_absolute_path(const(sc_path)* parent, sc_path* child);
	void sc_pkcs15_free_object_content(sc_pkcs15_object*);
	int sc_pkcs15_allocate_object_content(sc_context*, sc_pkcs15_object*, const(ubyte)*, size_t);
	sc_supported_algo_info* sc_pkcs15_get_supported_algo(sc_pkcs15_card*, uint, uint);
	int sc_pkcs15_add_supported_algo_ref(sc_pkcs15_object*, sc_supported_algo_info*);
	int sc_pkcs15_fix_ec_parameters(sc_context*, sc_ec_parameters*);
	int sc_pkcs15_convert_bignum(sc_pkcs15_bignum* dst, const(void)* bignum);
	int sc_pkcs15_convert_prkey(sc_pkcs15_prkey* key, void* evp_key);
	int sc_pkcs15_convert_pubkey(sc_pkcs15_pubkey* key, void* evp_key);
	char* sc_pkcs15_get_lastupdate(sc_pkcs15_card* p15card);
	int sc_pkcs15_get_generalized_time(sc_context* ctx, char** out_);
	struct sc_pkcs15emu_opt
	{
		scconf_block* blk;
		uint flags;
	}
	enum SC_PKCS15EMU_FLAGS_NO_CHECK = 1;
	extern int sc_pkcs15_bind_synthetic(sc_pkcs15_card*);
	extern int sc_pkcs15_is_emulation_only(sc_card*);
	int sc_pkcs15emu_object_add(sc_pkcs15_card*, uint, const(sc_pkcs15_object)*, const(void)*);
	int sc_pkcs15emu_add_pin_obj(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_auth_info)*);
	int sc_pkcs15emu_add_rsa_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
	int sc_pkcs15emu_add_rsa_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
	int sc_pkcs15emu_add_ec_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
	int sc_pkcs15emu_add_ec_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
	int sc_pkcs15emu_add_x509_cert(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_cert_info)*);
	int sc_pkcs15emu_add_data_object(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_data_info)*);
}
