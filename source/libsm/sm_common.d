// D import file generated from 'sm_common.d' renamed to 'sm_common.d' (method [only for original == header file] results in very compact code and obviates to overhaul comments now)
// Functions exported from "libsmm-local.*" ; TODO check if this module will finally be required at all

module libsm.sm_common;
version (ENABLE_SM)
{
	import core.stdc.config : c_long;
	import libopensc.opensc : sc_context;
	import deimos.openssl.des : DES_LONG, DES_cblock, const_DES_cblock, DES_key_schedule;
	extern (C) 
	{
		DES_LONG DES_cbc_cksum_3des(const(ubyte)* in_, DES_cblock* output, c_long length, DES_key_schedule* schedule, DES_key_schedule* schedule2, const_DES_cblock* ivec);
		DES_LONG DES_cbc_cksum_3des_emv96(const(ubyte)* in_, DES_cblock* output, c_long length, DES_key_schedule* schedule, DES_key_schedule* schedule2, const_DES_cblock* ivec);
		int sm_encrypt_des_ecb3(ubyte* key, ubyte* data, int data_len, ubyte** out_, int* out_len);
		int sm_encrypt_des_cbc3(sc_context* ctx, ubyte* key, const(ubyte)* in_, size_t in_len, ubyte** out_, size_t* out_len, int not_force_pad);
		int sm_decrypt_des_cbc3(sc_context* ctx, ubyte* key, ubyte* data, size_t data_len, ubyte** out_, size_t* out_len);
		void sm_incr_ssc(ubyte* ssc, size_t ssc_len);
	}
}
