// D import file generated from 'sm.d' renamed to 'sm.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions within struct sm_module_operations exported from "libsmm-local.*",
// all other functions exported from "libopensc.*"

module libopensc.sm;

version (ENABLE_SM)
{
	import core.stdc.config : c_ulong;

	import libopensc.errors;
	import libopensc.types;
	import libopensc.opensc : sc_card, sc_context;

	extern (C) 
	{
		enum SHA_DIGEST_LENGTH = 20;
		enum SHA1_DIGEST_LENGTH = 20;
		enum SHA256_DIGEST_LENGTH = 32;
		enum 
		{
			SM_TYPE_GP_SCP01 = 256,
			SM_TYPE_CWA14890 = 1024,
			SM_TYPE_DH_RSA = 1280,
		}
		enum 
		{
			SM_MODE_NONE = 0,
			SM_MODE_ACL = 256,
			SM_MODE_TRANSMIT = 512,
		}
		enum 
		{
			SM_CMD_INITIALIZE = 16,
			SM_CMD_MUTUAL_AUTHENTICATION = 32,
			SM_CMD_RSA = 256,
			SM_CMD_RSA_GENERATE = 257,
			SM_CMD_RSA_UPDATE = 258,
			SM_CMD_RSA_READ_PUBLIC = 259,
			SM_CMD_FILE = 512,
			SM_CMD_FILE_READ = 513,
			SM_CMD_FILE_UPDATE = 514,
			SM_CMD_FILE_CREATE = 515,
			SM_CMD_FILE_DELETE = 516,
			SM_CMD_FILE_ERASE = 517,
			SM_CMD_PIN = 768,
			SM_CMD_PIN_VERIFY = 769,
			SM_CMD_PIN_RESET = 770,
			SM_CMD_PIN_SET_PIN = 771,
			SM_CMD_PSO = 1024,
			SM_CMD_PSO_DST = 1025,
			SM_CMD_APDU = 1280,
			SM_CMD_APDU_TRANSMIT = 1281,
			SM_CMD_APDU_RAW = 1282,
			SM_CMD_APPLET = 1536,
			SM_CMD_APPLET_DELETE = 1537,
			SM_CMD_APPLET_LOAD = 1538,
			SM_CMD_APPLET_INSTALL = 1539,
			SM_CMD_EXTERNAL_AUTH = 1792,
			SM_CMD_EXTERNAL_AUTH_INIT = 1793,
			SM_CMD_EXTERNAL_AUTH_CHALLENGE = 1794,
			SM_CMD_EXTERNAL_AUTH_DOIT = 1795,
			SM_CMD_SDO_UPDATE = 2048,
			SM_CMD_FINALIZE = 2304,
		}
		enum SM_RESPONSE_CONTEXT_TAG = 161;
		enum SM_RESPONSE_CONTEXT_DATA_TAG = 162;
		enum SM_MAX_DATA_SIZE = 224;
		enum SM_SMALL_CHALLENGE_LEN = 8;
		enum SM_GP_SECURITY_NO = 0;
		enum SM_GP_SECURITY_MAC = 1;
		enum SM_GP_SECURITY_ENC = 3;
		struct sm_type_params_gp
		{
			uint level;
			uint index;
			uint version_;
			sc_cplc cplc;
		}
		struct sm_gp_keyset
		{
			int version_;
			int index;
			ubyte[16] enc;
			ubyte[16] mac;
			ubyte[16] kek;
			ubyte[48] kmc;
			uint kmc_len;
		}
		struct sm_gp_session
		{
			sm_gp_keyset gp_keyset;
			sm_type_params_gp params;
			ubyte[SM_SMALL_CHALLENGE_LEN] host_challenge;
			ubyte[SM_SMALL_CHALLENGE_LEN] card_challenge;
			ubyte* session_enc;
			ubyte* session_mac;
			ubyte* session_kek;
			ubyte[8] mac_icv;
		}
		struct sm_type_params_cwa
		{
			sc_crt crt_at;
		}
		struct sm_cwa_keyset
		{
			uint sdo_reference;
			ubyte[16] enc;
			ubyte[16] mac;
		}
		struct sm_cwa_token_data
		{
			ubyte[8] sn;
			ubyte[8] rnd;
			ubyte[32] k;
		}
		struct sm_cwa_session
		{
			sm_cwa_keyset cwa_keyset;
			sm_type_params_cwa params;
			sm_cwa_token_data icc;
			sm_cwa_token_data ifd;
			ubyte[16] session_enc;
			ubyte[16] session_mac;
			ubyte[8] ssc;
			ubyte[SM_SMALL_CHALLENGE_LEN] host_challenge;
			ubyte[SM_SMALL_CHALLENGE_LEN] card_challenge;
			ubyte[72] mdata;
			size_t mdata_len;
		}
		struct sm_dh_session
		{
			sc_tlv_data g;
			sc_tlv_data N;
			sc_tlv_data ifd_p;
			sc_tlv_data ifd_y;
			sc_tlv_data icc_p;
			sc_tlv_data shared_secret;
			ubyte[16] session_enc;
			ubyte[16] session_mac;
			ubyte[32] card_challenge;
			ubyte[8] ssc;
		}
		struct sm_info
		{
			char[64] config_section;
			uint card_type;
			uint cmd;
			void* cmd_data;
			uint sm_type;
			union anonymous
			{
				sm_gp_session gp;
				sm_cwa_session cwa;
				sm_dh_session dh;
			}
			anonymous session;
			sc_serial_number serialnr;
			uint security_condition;
			sc_path current_path_df;
			sc_path current_path_ef;
			sc_aid current_aid;
			ubyte* rdata;
			size_t rdata_len;
		}
		struct sm_card_response
		{
			int num;
			ubyte[SC_MAX_APDU_BUFFER_SIZE] data;
			size_t data_len;
			ubyte[8] mac;
			size_t mac_len;
			ubyte sw1;
			ubyte sw2;
			sm_card_response* next;
			sm_card_response* prev;
		}
		alias sm_1_tf = int function(sc_card* card);
		alias sm_2_tf = int function(sc_card* card, sc_apdu* apdu, sc_apdu** sm_apdu);
		struct sm_card_operations
		{
			sm_1_tf open;
			sm_2_tf get_sm_apdu;
			sm_2_tf free_sm_apdu;
			sm_1_tf close;
			int function(sc_card* card, uint idx, ubyte* buf, size_t count) read_binary;
			int function(sc_card* card, uint idx, const(ubyte)* buf, size_t count) update_binary;
		}
		struct sm_module_operations
		{
			int function(sc_context* ctx, sm_info* info, sc_remote_data* rdata) initialize;
			int function(sc_context* ctx, sm_info* info, ubyte* init_data, size_t init_len, sc_remote_data* out_) get_apdus;
			int function(sc_context* ctx, sm_info* info, sc_remote_data* rdata, ubyte* out_, size_t out_len) finalize;
			int function(sc_context* ctx, const(char)* data) module_init;
			int function(sc_context* ctx) module_cleanup;
			int function(sc_context* ctx, sm_info* info, char* out_) test;
		}
		struct sm_module
		{
			char[128] filename;
			void* handle;
			sm_module_operations ops;
		}
		struct sm_context
		{
			char[64] config_section;
			uint sm_mode;
			uint sm_flags;
			sm_info info;
			sm_card_operations ops;
			sm_module module_;
			c_ulong function() app_lock;
			void function() app_unlock;
		}
		int sc_sm_parse_answer(sc_card*, ubyte*, size_t, sm_card_response*);
		int sc_sm_update_apdu_response(sc_card*, ubyte*, size_t, int, sc_apdu*);
		int sc_sm_single_transmit(sc_card*, sc_apdu*);
		int sc_sm_stop(sc_card* card);
	}
}
