// No functions exported from "libopensc.*"

module libopensc.cardctl;

//import libopensc.types;

extern (C)
{
//	uint _CTL_PREFIX(ubyte a, ubyte b, ubyte c)  { return ((a << 24) | (b << 16) | (c << 8)); }
	enum
	{
		SC_CARDCTL_GENERIC_BASE = 0x0000_0000,
		SC_CARDCTL_ERASE_CARD,
		SC_CARDCTL_GET_DEFAULT_KEY,
		SC_CARDCTL_LIFECYCLE_GET,
		SC_CARDCTL_LIFECYCLE_SET,
		SC_CARDCTL_GET_SERIALNR,
		SC_CARDCTL_GET_SE_INFO,
		SC_CARDCTL_GET_CHV_REFERENCE_IN_SE,
		SC_CARDCTL_PKCS11_INIT_TOKEN,
		SC_CARDCTL_PKCS11_INIT_PIN,
	}

	enum
	{
		SC_CARDCTRL_LIFECYCLE_ADMIN,
		SC_CARDCTRL_LIFECYCLE_USER,
		SC_CARDCTRL_LIFECYCLE_OTHER,
	}

	struct sc_cardctl_default_key
	{
		int method;
		int key_ref;
		size_t len;
		ubyte* key_data;
	}

	struct sc_cardctl_pkcs11_init_token
	{
		const(ubyte)* so_pin;
		size_t so_pin_len;
		const(char)* label;
	}
//	alias sc_cardctl_pkcs11_init_token_t = sc_cardctl_pkcs11_init_token;

	struct sc_cardctl_pkcs11_init_pin
	{
		const(ubyte)* pin;
		size_t pin_len;
	}
//	alias sc_cardctl_pkcs11_init_pin_t = sc_cardctl_pkcs11_init_pin;
}
