#
# PKCS15 r/w profile for Athena LASER card
#
cardinfo {
	label	= "LASER";
	manufacturer	= "Athena";
	max-pin-length	= 10;
	min-pin-length	= 4;
	pin-encoding	= ascii-numeric;
}

pkcs15 {
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update      = no;
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
	auth-id		= 0x20;
	attempts	= 10;
	max-length	= 10;
	min-length	= 4;
	flags	= case-sensitive, initialized;
	reference = 0x20
}
PIN so-pin {
	auth-id		= 0x10;
	attempts	= 3;
	max-length	= 10;
	min-length	= 4;
	flags		= case-sensitive, initialized, soPin;
	reference	= 0x10
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
	DF MF {
		ACL = *=CHV4;

		DF Athena-AppDF {
			ACL = *=NONE;
			ACL = CREATE=CHV32, CRYPTO=NEVER;
			file-id		= 3000;
			size = 40;

			DF private-DF {
				ACL = *=NEVER;
				ACL = CREATE=CHV32, DELETE=NONE;
				file-id		= 3002;
				size		= 40;

				# Private RSA keys
				EF laser-private-key-attributes   {
					ACL	= WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=NONE;
					file-id	= 0200;
				}
				EF template-private-key {
					file-id	= 0041;
					type	= internal-ef;
					ACL	= *=NEVER;
					ACL	= DELETE-SELF=NONE;
					ACL	= READ=CHV32, UPDATE=CHV32, GENERATE=CHV32, PIN-RESET=CHV32, CRYPTO=CHV32;
				}
			}

			DF public-DF {
				ACL = *=NEVER;
				ACL = CREATE=NONE, DELETE=NONE;
				file-id		= 3001;
				size		= 80;

				# Certificate
				EF Athena-certificate-info  {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}
				EF template-certificate {
					file-id		= 2000;
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}

				#Public Key
				EF laser-public-key-attributes {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=NONE;
					file-id	= 0140;
				}
				EF template-public-key {
					file-id	= 0081;
					type	= internal-ef;
					ACL	= *=NONE;
					ACL	= UPDATE=NEVER, ADMIN=NEVER;
				}
			}

			EF Athena-token-info {
				file-id	= C000;
				size	= 36;
				ACL	= WRITE=CHV4, UPDATE=CHV4, READ=NONE, ERASE=NEVER;
			}
		}
	}
}
