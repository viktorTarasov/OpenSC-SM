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
    # Put certificates into the CDF itself?
    # direct-certificates = yes;
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
					file-id	= 0040;		# Private Exchange key appear in cmapfile
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
				EF laser-certificate-attributes  {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=NONE;
					file-id	= 8400;		# Certificate object appear in cmapfile
				}

				#Public Key
				EF laser-public-key-attributes {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=NONE;
					file-id	= 0140;
				}
				EF template-public-key {
					file-id	= 0080;
					type	= internal-ef;
					ACL	= *=NONE;
					ACL	= UPDATE=NEVER, ADMIN=NEVER;
				}

				#Public DATA object
				EF laser-public-data-attributes {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, DELETE-SELF=NONE;
					file-id	= 0640;
				}

				#CMAP ile
				EF laser-cmap-attributes {
					ACL = WRITE=CHV48, UPDATE=CHV48, READ=NONE, DELETE-SELF=CHV48;
					file-id	= 867F;
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
