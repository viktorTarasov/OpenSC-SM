// D import file generated from 'opensc.d' renamed to 'opensc.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions exported from "libopensc.*"

module libopensc.opensc;
import core.stdc.stdio : FILE;
extern (C) 
{
	private import libopensc.internal;
	public import common.simclist;
	public import scconf.scconf;
	public import libopensc.errors;
	public import libopensc.types;
	version (ENABLE_SM)
	{
		import libopensc.sm;
	}
	enum 
	{
		SC_SEC_OPERATION_DECIPHER = 1,
		SC_SEC_OPERATION_SIGN = 2,
		SC_SEC_OPERATION_AUTHENTICATE = 3,
		SC_SEC_OPERATION_DERIVE = 4,
	}
	enum 
	{
		SC_SEC_ENV_ALG_REF_PRESENT = 1,
		SC_SEC_ENV_FILE_REF_PRESENT = 2,
		SC_SEC_ENV_KEY_REF_PRESENT = 4,
		SC_SEC_ENV_KEY_REF_ASYMMETRIC = 8,
		SC_SEC_ENV_ALG_PRESENT = 16,
	}
	alias SC_ALGORITHM_t = int;
	enum : SC_ALGORITHM_t
	{
		SC_ALGORITHM_RSA = 0,
		SC_ALGORITHM_DSA = 1,
		SC_ALGORITHM_EC = 2,
		SC_ALGORITHM_GOSTR3410 = 3,
		SC_ALGORITHM_DES = 64,
		SC_ALGORITHM_3DES = 65,
		SC_ALGORITHM_GOST = 66,
		SC_ALGORITHM_MD5 = 128,
		SC_ALGORITHM_SHA1 = 129,
		SC_ALGORITHM_GOSTR3411 = 130,
		SC_ALGORITHM_PBKDF2 = 192,
		SC_ALGORITHM_PBES2 = 256,
		SC_ALGORITHM_ONBOARD_KEY_GEN = 2147483648u,
		SC_ALGORITHM_NEED_USAGE = 1073741824,
		SC_ALGORITHM_SPECIFIC_FLAGS = 131071,
		SC_ALGORITHM_RSA_RAW = 1,
		SC_ALGORITHM_RSA_PADS = 14,
		SC_ALGORITHM_RSA_PAD_NONE = 0,
		SC_ALGORITHM_RSA_PAD_PKCS1 = 2,
		SC_ALGORITHM_RSA_PAD_ANSI = 4,
		SC_ALGORITHM_RSA_PAD_ISO9796 = 8,
		SC_ALGORITHM_RSA_HASH_NONE = 16,
		SC_ALGORITHM_RSA_HASH_SHA1 = 32,
		SC_ALGORITHM_RSA_HASH_MD5 = 64,
		SC_ALGORITHM_RSA_HASH_MD5_SHA1 = 128,
		SC_ALGORITHM_RSA_HASH_RIPEMD160 = 256,
		SC_ALGORITHM_RSA_HASH_SHA256 = 512,
		SC_ALGORITHM_RSA_HASH_SHA384 = 1024,
		SC_ALGORITHM_RSA_HASH_SHA512 = 2048,
		SC_ALGORITHM_RSA_HASH_SHA224 = 4096,
		SC_ALGORITHM_RSA_HASHES = 8160,
		SC_ALGORITHM_GOSTR3410_RAW = 8192,
		SC_ALGORITHM_GOSTR3410_HASH_NONE = 16384,
		SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411 = 32768,
		SC_ALGORITHM_GOSTR3410_HASHES = 32768,
		SC_ALGORITHM_ECDSA_RAW = 65536,
		SC_ALGORITHM_ECDH_CDH_RAW = 131072,
		SC_ALGORITHM_ECDSA_HASH_NONE = SC_ALGORITHM_RSA_HASH_NONE,
		SC_ALGORITHM_ECDSA_HASH_SHA1 = SC_ALGORITHM_RSA_HASH_SHA1,
		SC_ALGORITHM_ECDSA_HASH_SHA224 = SC_ALGORITHM_RSA_HASH_SHA224,
		SC_ALGORITHM_ECDSA_HASH_SHA256 = SC_ALGORITHM_RSA_HASH_SHA256,
		SC_ALGORITHM_ECDSA_HASH_SHA384 = SC_ALGORITHM_RSA_HASH_SHA384,
		SC_ALGORITHM_ECDSA_HASH_SHA512 = SC_ALGORITHM_RSA_HASH_SHA512,
		SC_ALGORITHM_ECDSA_HASHES = SC_ALGORITHM_ECDSA_HASH_SHA1 | SC_ALGORITHM_ECDSA_HASH_SHA224 | SC_ALGORITHM_ECDSA_HASH_SHA256 | SC_ALGORITHM_ECDSA_HASH_SHA384 | SC_ALGORITHM_ECDSA_HASH_SHA512,
		SC_ALGORITHM_RAW_MASK = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_GOSTR3410_RAW | SC_ALGORITHM_ECDSA_RAW,
		SC_ALGORITHM_EXT_EC_F_P = 1,
		SC_ALGORITHM_EXT_EC_F_2M = 2,
		SC_ALGORITHM_EXT_EC_ECPARAMETERS = 4,
		SC_ALGORITHM_EXT_EC_NAMEDCURVE = 8,
		SC_ALGORITHM_EXT_EC_UNCOMPRESES = 16,
		SC_ALGORITHM_EXT_EC_COMPRESS = 32,
	}
	enum 
	{
		SC_EVENT_CARD_INSERTED = 1,
		SC_EVENT_CARD_REMOVED = 2,
		SC_EVENT_CARD_EVENTS = SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED,
		SC_EVENT_READER_ATTACHED = 4,
		SC_EVENT_READER_DETACHED = 8,
		SC_EVENT_READER_EVENTS = SC_EVENT_READER_ATTACHED | SC_EVENT_READER_DETACHED,
	}
	struct sc_supported_algo_info
	{
		uint reference;
		uint mechanism;
		uint operations;
		sc_object_id algo_id;
		uint algo_ref;
	}
	struct sc_security_env
	{
		c_ulong flags;
		int operation;
		uint algorithm;
		uint algorithm_flags;
		uint algorithm_ref;
		sc_path file_ref;
		ubyte[8] key_ref;
		size_t key_ref_len;
		sc_supported_algo_info[SC_MAX_SUPPORTED_ALGORITHMS] supported_algos;
	}
	struct sc_algorithm_id
	{
		uint algorithm;
		sc_object_id oid;
		void* params;
	}
	struct sc_pbkdf2_params
	{
		ubyte[16] salt;
		size_t salt_len;
		int iterations;
		size_t key_length;
		sc_algorithm_id hash_alg;
	}
	struct sc_pbes2_params
	{
		sc_algorithm_id derivation_alg;
		sc_algorithm_id key_encr_alg;
	}
	struct sc_ec_parameters
	{
		char* named_curve;
		sc_object_id id;
		sc_lv_data der;
		int type;
		size_t field_length;
	}
	struct sc_algorithm_info
	{
		uint algorithm;
		uint key_length;
		uint flags;
		union anonymous
		{
			struct sc_rsa_info
			{
				c_ulong exponent;
			}
			sc_rsa_info _rsa;
			struct sc_ec_info
			{
				uint ext_flags;
				sc_ec_parameters params;
			}
			sc_ec_info _ec;
		}
		anonymous u;
	}
	struct sc_app_info
	{
		char* label;
		sc_aid aid;
		sc_ddo ddo;
		sc_path path;
		int rec_nr;
	}
	struct sc_ef_atr
	{
		ubyte card_service;
		ubyte df_selection;
		size_t unit_size;
		ubyte card_capabilities;
		sc_aid aid;
		ubyte[6] pre_issuing;
		size_t pre_issuing_len;
		ubyte[16] issuer_data;
		size_t issuer_data_len;
		sc_object_id allocation_oid;
		uint status;
	}
	struct sc_card_cache
	{
		sc_path current_path;
		sc_file* current_ef;
		sc_file* current_df;
		int valid;
	}
	enum 
	{
		SC_PROTO_T0 = 1,
		SC_PROTO_T1 = 2,
		SC_PROTO_RAW = 4096,
		SC_PROTO_ANY = 4294967295u,
	}
	struct sc_reader_driver
	{
		immutable(char)* name;
		immutable(char)* short_name;
		sc_reader_operations* ops;
		size_t max_send_size;
		size_t max_recv_size;
		void* dll;
	}
	enum 
	{
		SC_READER_CARD_PRESENT = 1,
		SC_READER_CARD_CHANGED = 2,
		SC_READER_CARD_INUSE = 4,
		SC_READER_CARD_EXCLUSIVE = 8,
		SC_READER_HAS_WAITING_AREA = 16,
		SC_READER_REMOVED = 32,
	}
	enum 
	{
		SC_READER_CAP_DISPLAY = 1,
		SC_READER_CAP_PIN_PAD = 2,
		SC_READER_CAP_PACE_EID = 4,
		SC_READER_CAP_PACE_ESIGN = 8,
		SC_READER_CAP_PACE_DESTROY_CHANNEL = 16,
		SC_READER_CAP_PACE_GENERIC = 32,
	}
	struct sc_reader
	{
		sc_context* ctx;
		const(sc_reader_driver)* driver;
		const(sc_reader_operations)* ops;
		void* drv_data;
		char* name;
		c_ulong flags;
		c_ulong capabilities;
		uint supported_protocols;
		uint active_protocol;
		sc_atr atr;
		struct _atr_info
		{
			ubyte* hist_bytes;
			size_t hist_bytes_len;
			int Fi;
			int f;
			int Di;
			int N;
			ubyte FI;
			ubyte DI;
		}
		_atr_info atr_info;
	}
	alias SC_PIN_CMD_t = uint;
	enum SC_PIN_CMD : SC_PIN_CMD_t
	{
		SC_PIN_CMD_VERIFY = 0,
		SC_PIN_CMD_CHANGE = 1,
		SC_PIN_CMD_UNBLOCK = 2,
		SC_PIN_CMD_GET_INFO = 3,
	}
	alias SC_PIN_CMD_FLAG_t = uint;
	enum : SC_PIN_CMD_FLAG_t
	{
		SC_PIN_CMD_USE_PINPAD = 1,
		SC_PIN_CMD_NEED_PADDING = 2,
		SC_PIN_CMD_IMPLICIT_CHANGE = 4,
	}
	enum 
	{
		SC_PIN_ENCODING_ASCII = 0,
		SC_PIN_ENCODING_BCD = 1,
		SC_PIN_ENCODING_GLP = 2,
	}
	struct sc_pin_cmd_pin
	{
		immutable(char)* prompt;
		const(ubyte)* data;
		int len;
		size_t min_length;
		size_t max_length;
		size_t stored_length;
		uint encoding;
		size_t pad_length;
		ubyte pad_char;
		size_t offset;
		size_t length_offset;
		int max_tries;
		int tries_left;
		sc_acl_entry[SC_MAX_SDO_ACLS] acls;
	}
	struct sc_pin_cmd_data
	{
		uint cmd;
		uint flags;
		uint pin_type;
		int pin_reference;
		sc_pin_cmd_pin pin1;
		sc_pin_cmd_pin pin2;
		sc_apdu* apdu;
	}
	alias reader_fun1_t = int function(sc_context* ctx);
	alias reader_fun2_t = int function(sc_reader* reader);
	struct sc_reader_operations
	{
		reader_fun1_t init;
		reader_fun1_t finish;
		reader_fun1_t detect_readers;
		reader_fun1_t cancel;
		reader_fun2_t release;
		reader_fun2_t detect_card_presence;
		reader_fun2_t connect;
		reader_fun2_t disconnect;
		int function(sc_reader* reader, sc_apdu* apdu) transmit;
		reader_fun2_t lock;
		reader_fun2_t unlock;
		int function(sc_reader* reader, uint proto) set_protocol;
		int function(sc_reader* reader, immutable(char)*) display_message;
		int function(sc_reader* reader, sc_pin_cmd_data*) perform_verify;
		int function(sc_reader* reader, void* establish_pace_channel_input, void* establish_pace_channel_output) perform_pace;
		int function(sc_context* ctx, uint event_mask, sc_reader** event_reader, uint* event, int timeout, void** reader_states) wait_for_event;
		int function(sc_reader*, int) reset;
		int function(sc_context* ctx, void* pcsc_context_handle, void* pcsc_card_handle) use_reader;
	}
	enum 
	{
		SC_CARD_FLAG_VENDOR_MASK = 4294901760u,
		SC_CARD_FLAG_RNG = 2,
	}
	alias SC_CARD_CAP_t = int;
	enum : SC_CARD_CAP_t
	{
		SC_CARD_CAP_APDU_EXT = 1,
		SC_CARD_CAP_RNG = 4,
		SC_CARD_CAP_USE_FCI_AC = 16,
		SC_CARD_CAP_ONLY_RAW_HASH = 64,
		SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED = 128,
	}
	struct sc_card
	{
		sc_context* ctx;
		sc_reader* reader;
		sc_atr atr;
		int type;
		c_ulong caps;
		c_ulong flags;
		int cla;
		size_t max_send_size;
		size_t max_recv_size;
		sc_app_info*[SC_MAX_CARD_APPS] app;
		int app_count;
		sc_file* ef_dir;
		sc_ef_atr* ef_atr;
		sc_algorithm_info* algorithms;
		int algorithm_count;
		int lock_count;
		sc_card_driver* driver;
		sc_card_operations* ops;
		immutable(char)* name;
		void* drv_data;
		int max_pin_len;
		sc_card_cache cache;
		sc_serial_number serialnr;
		sc_version version_;
		void* mutex;
		version (ENABLE_SM)
		{
			sm_context sm_ctx;
		}
		uint magic;
	}
	alias card_fun1_t = int function(sc_card* card);
	alias card_fun2_t = int function(sc_card* card, uint idxORrec_nr, ubyte* buf, size_t count, c_ulong flags);
	alias card_fun3_t = int function(sc_card* card, uint idxORrec_nr, const(ubyte)* buf, size_t count, c_ulong flags);
	alias card_fun4_t = int function(sc_card* card, const(ubyte)* data, size_t data_len, ubyte* out_, size_t outlen);
	alias erase_binary_tf = int function(sc_card* card, uint idx, size_t count, c_ulong flags);
	alias append_record_tf = int function(sc_card* card, const(ubyte)* buf, size_t count, c_ulong flags);
	alias select_file_tf = int function(sc_card* card, const(sc_path)* path, sc_file** file_out);
	alias get_response_tf = int function(sc_card* card, size_t* count, ubyte* buf);
	alias get_challenge_tf = int function(sc_card* card, ubyte* buf, size_t count);
	alias verify_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* data, size_t data_len, int* tries_left);
	alias restore_security_env_tf = int function(sc_card* card, int se_num);
	alias set_security_env_tf = int function(sc_card* card, const(sc_security_env)* env, int se_num);
	alias change_reference_data_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* old, size_t oldlen, const(ubyte)* newref, size_t newlen, int* tries_left);
	alias reset_retry_counter_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* puk, size_t puklen, const(ubyte)* newref, size_t newlen);
	alias create_file_tf = int function(sc_card* card, sc_file* file);
	alias delete_file_tf = int function(sc_card* card, const(sc_path)* path);
	alias list_files_tf = int function(sc_card* card, ubyte* buf, size_t buflen);
	alias check_sw_tf = int function(sc_card* card, uint sw1, uint sw2);
	alias card_ctl_tf = int function(sc_card* card, c_ulong request, void* data);
	alias process_fci_tf = int function(sc_card* card, sc_file* file, const(ubyte)* buf, size_t buflen);
	alias construct_fci_tf = int function(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen);
	alias pin_cmd_tf = int function(sc_card* card, sc_pin_cmd_data* data, int* tries_left);
	alias get_data_tf = int function(sc_card* card, uint, ubyte*, size_t);
	alias put_data_tf = int function(sc_card* card, uint, const(ubyte)*, size_t);
	alias delete_record_tf = int function(sc_card* card, uint rec_nr);
	alias read_public_key_tf = int function(sc_card* card, uint, sc_path* path, uint, uint, ubyte**, size_t*);
	struct sc_card_operations
	{
		card_fun1_t match_card;
		card_fun1_t init;
		card_fun1_t finish;
		card_fun2_t read_binary;
		card_fun3_t write_binary;
		card_fun3_t update_binary;
		erase_binary_tf erase_binary;
		card_fun2_t read_record;
		card_fun3_t write_record;
		append_record_tf append_record;
		card_fun3_t update_record;
		select_file_tf select_file;
		get_response_tf get_response;
		get_challenge_tf get_challenge;
		deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") verify_tf verify;
		card_fun1_t logout;
		restore_security_env_tf restore_security_env;
		set_security_env_tf set_security_env;
		card_fun4_t decipher;
		card_fun4_t compute_signature;
		deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") change_reference_data_tf change_reference_data;
		deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") reset_retry_counter_tf reset_retry_counter;
		create_file_tf create_file;
		delete_file_tf delete_file;
		list_files_tf list_files;
		check_sw_tf check_sw;
		card_ctl_tf card_ctl;
		process_fci_tf process_fci;
		construct_fci_tf construct_fci;
		pin_cmd_tf pin_cmd;
		get_data_tf get_data;
		put_data_tf put_data;
		delete_record_tf delete_record;
		read_public_key_tf read_public_key;
	}
	struct sc_card_driver
	{
		immutable(char)* name;
		immutable(char)* short_name;
		sc_card_operations* ops;
		immutable(sc_atr_table)* atr_map;
		uint natrs;
		void* dll;
	}
	struct sc_thread_context_t
	{
		uint ver;
		int function(void**) create_mutex;
		int function(void*) lock_mutex;
		int function(void*) unlock_mutex;
		int function(void*) destroy_mutex;
		c_ulong function() thread_id;
	}
	struct sc_context
	{
		scconf_context* conf;
		scconf_block*[3] conf_blocks;
		char* app_name;
		int debug_;
		int paranoid_memory;
		int enable_default_driver;
		FILE* debug_file;
		char* debug_filename;
		char* preferred_language;
		list_t readers;
		sc_reader_driver* reader_driver;
		void* reader_drv_data;
		sc_card_driver*[SC_MAX_CARD_DRIVERS] card_drivers;
		sc_card_driver* forced_driver;
		sc_thread_context_t* thread_ctx;
		void* mutex;
		uint magic;
	}
	int sc_transmit_apdu(sc_card* card, sc_apdu* apdu);
	void sc_format_apdu(sc_card* card, sc_apdu* apdu, int apdu_case, int ins, int p1, int p2);
	int sc_check_apdu(sc_card* card, const(sc_apdu)* apdu);
	int sc_bytes2apdu(sc_context* ctx, const(ubyte)* buf, size_t len, sc_apdu* apdu);
	int sc_check_sw(sc_card* card, uint sw1, uint sw2);
	deprecated("Please use sc_context_create() instead") int sc_establish_context(sc_context** ctx, const(char)* app_name);
	struct sc_context_param_t
	{
		uint ver;
		const(char)* app_name;
		c_ulong flags;
		sc_thread_context_t* thread_ctx;
	}
	int sc_context_repair(sc_context** ctx);
	int sc_context_create(sc_context** ctx, const(sc_context_param_t)* parm);
	int sc_release_context(sc_context* ctx);
	int sc_ctx_detect_readers(sc_context* ctx);
	sc_reader* sc_ctx_get_reader(sc_context* ctx, uint i);
	int sc_ctx_use_reader(sc_context* ctx, void* pcsc_context_handle, void* pcsc_card_handle);
	sc_reader* sc_ctx_get_reader_by_name(sc_context* ctx, const(char)* name);
	sc_reader* sc_ctx_get_reader_by_id(sc_context* ctx, uint id);
	uint sc_ctx_get_reader_count(sc_context* ctx);
	int _sc_delete_reader(sc_context* ctx, sc_reader* reader);
	int sc_ctx_log_to_file(sc_context* ctx, const(char)* filename);
	int sc_set_card_driver(sc_context* ctx, const(char)* short_name);
	int sc_connect_card(sc_reader* reader, sc_card** card);
	int sc_disconnect_card(sc_card* card);
	int sc_detect_card_presence(sc_reader* reader);
	int sc_wait_for_event(sc_context* ctx, uint event_mask, sc_reader** event_reader, uint* event, int timeout, void** reader_states);
	int sc_reset(sc_card* card, int do_cold_reset);
	int sc_cancel(sc_context* ctx);
	int sc_lock(sc_card* card);
	int sc_unlock(sc_card* card);
	int sc_select_file(sc_card* card, const(sc_path)* path, sc_file** file);
	int sc_list_files(sc_card* card, ubyte* buf, size_t buflen);
	int sc_read_binary(sc_card* card, uint idx, ubyte* buf, size_t count, c_ulong flags);
	int sc_write_binary(sc_card* card, uint idx, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_update_binary(sc_card* card, uint idx, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_erase_binary(sc_card* card, uint idx, size_t count, c_ulong flags);
	enum 
	{
		SC_RECORD_EF_ID_MASK = 31LU,
		SC_RECORD_BY_REC_ID = 0LU,
		SC_RECORD_BY_REC_NR = 256LU,
		SC_RECORD_CURRENT = 0LU,
	}
	int sc_read_record(sc_card* card, uint rec_nr, ubyte* buf, size_t count, c_ulong flags);
	int sc_write_record(sc_card* card, uint rec_nr, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_append_record(sc_card* card, const ubyte* buf, size_t count, c_ulong flags);
	int sc_update_record(sc_card* card, uint rec_nr, const ubyte* buf, size_t count, c_ulong flags);
	int sc_delete_record(sc_card* card, uint rec_nr);
	int sc_get_data(sc_card*, uint, ubyte*, size_t);
	int sc_put_data(sc_card*, uint, const ubyte*, size_t);
	int sc_get_challenge(sc_card* card, ubyte* rndout, size_t len);
	int sc_restore_security_env(sc_card* card, int se_num);
	int sc_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num);
	int sc_decipher(sc_card* card, const(ubyte)* crgram, size_t crgram_len, ubyte* out_, size_t outlen);
	int sc_compute_signature(sc_card* card, const(ubyte)* data, size_t data_len, ubyte* out_, size_t outlen);
	int sc_verify(sc_card* card, uint type, int ref_, const(ubyte)* buf, size_t buflen, int* tries_left);
	int sc_logout(sc_card* card);
	int sc_pin_cmd(sc_card* card, sc_pin_cmd_data*, int* tries_left);
	int sc_change_reference_data(sc_card* card, uint type, int ref_, const(ubyte)* old, size_t oldlen, const(ubyte)* newref, size_t newlen, int* tries_left);
	int sc_reset_retry_counter(sc_card* card, uint type, int ref_, const(ubyte)* puk, size_t puklen, const(ubyte)* newref, size_t newlen);
	int sc_build_pin(ubyte* buf, size_t buflen, sc_pin_cmd_pin* pin, int pad);
	int sc_create_file(sc_card* card, sc_file* file);
	int sc_delete_file(sc_card* card, const(sc_path)* path);
	int sc_card_ctl(sc_card* card, c_ulong command, void* arg);
	int sc_file_valid(const(sc_file)* file);
	sc_file* sc_file_new();
	void sc_file_free(sc_file* file);
	void sc_file_dup(sc_file** dest, const(sc_file)* src);
	int sc_file_add_acl_entry(sc_file* file, uint operation, uint method, c_ulong key_ref);
	const(sc_acl_entry)* sc_file_get_acl_entry(const(sc_file)* file, uint operation);
	void sc_file_clear_acl_entries(sc_file* file, uint operation);
	int sc_file_set_sec_attr(sc_file* file, const(ubyte)* sec_attr, size_t sec_attr_len);
	int sc_file_set_prop_attr(sc_file* file, const(ubyte)* prop_attr, size_t prop_attr_len);
	int sc_file_set_type_attr(sc_file* file, const(ubyte)* type_attr, size_t type_attr_len);
	int sc_file_set_content(sc_file* file, const(ubyte)* content, size_t content_len);
	int sc_path_set(sc_path* path, int type, const(ubyte)* id, size_t id_len, int index, int count);
	void sc_format_path(const(char)* path_in, sc_path* path_out);
	const(char)* sc_print_path(const(sc_path)* path);
	int sc_path_print(char* buf, size_t buflen, const(sc_path)* path);
	int sc_compare_path(const(sc_path)* patha, const(sc_path)* pathb);
	int sc_concatenate_path(sc_path* d, const(sc_path)* p1, const(sc_path)* p2);
	int sc_append_path(sc_path* dest, const(sc_path)* src);
	int sc_compare_path_prefix(const(sc_path)* prefix, const(sc_path)* path);
	int sc_append_path_id(sc_path* dest, const(ubyte)* id, size_t idlen);
	int sc_append_file_id(sc_path* dest, uint fid);
	const(sc_path)* sc_get_mf_path();
	int sc_hex_to_bin(const(char)* in_, ubyte* out_, size_t* outlen);
	int sc_bin_to_hex(const(ubyte)*, size_t, char*, size_t, int separator);
	size_t sc_right_trim(ubyte* buf, size_t len);
	scconf_block* sc_get_conf_block(sc_context* ctx, const(char)* name1, const(char)* name2, int priority);
	void sc_init_oid(sc_object_id* oid);
	int sc_format_oid(sc_object_id* oid, const(char)* in_);
	int sc_compare_oid(const(sc_object_id)* oid1, const(sc_object_id)* oid2);
	int sc_valid_oid(const(sc_object_id)* oid);
	int sc_base64_encode(const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen, size_t linelength);
	int sc_base64_decode(const(char)* in_, ubyte* out_, size_t outlen);
	void sc_mem_clear(void* ptr, size_t len);
	void* sc_mem_alloc_secure(sc_context* ctx, size_t len);
	int sc_mem_reverse(ubyte* buf, size_t len);
	int sc_get_cache_dir(sc_context* ctx, char* buf, size_t bufsize);
	int sc_make_cache_dir(sc_context* ctx);
	int sc_enum_apps(sc_card* card);
	sc_app_info* sc_find_app(sc_card* card, sc_aid* aid);
	void sc_free_apps(sc_card* card);
	int sc_parse_ef_atr(sc_card* card);
	void sc_free_ef_atr(sc_card* card);
	int sc_update_dir(sc_card* card, sc_app_info* app);
	void sc_print_cache(sc_card* card);
	sc_algorithm_info* sc_card_find_rsa_alg(sc_card* card, uint key_length);
	sc_algorithm_info* sc_card_find_ec_alg(sc_card* card, uint field_length, sc_object_id* curve_oid);
	sc_algorithm_info* sc_card_find_gostr3410_alg(sc_card* card, uint key_length);
	scconf_block* sc_match_atr_block(sc_context* ctx, sc_card_driver* driver, sc_atr* atr);
	uint sc_crc32(ubyte* value, size_t len);
	void sc_remote_data_init(sc_remote_data* rdata);
	int sc_copy_ec_params(sc_ec_parameters*, sc_ec_parameters*);
	struct sc_card_error
	{
		uint SWs;
		int errorno;
		const(char)* errorstr;
	}
	__gshared const(char)* sc_get_version();
	__gshared sc_card_driver* sc_get_iso7816_driver();
}
