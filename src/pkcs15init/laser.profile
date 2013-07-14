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
	max-length	= 16;
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
		ACL = *=NONE;
		EF Athena-SoPIN {
			ACL = *=NONE;
			ACL = UPDATE=CHV16, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NEVER, PIN-RESET=NEVER, ADMIN=NEVER, READ=NEVER;
			file-id	= 0010;
			size	= 16;
			type	= internal-ef;
			structure = 8;
			content	= "81083030303030303030";
			prop-attr = "8001000033040A00000000001010";
		}

		EF Athena-UserPIN {
			ACL = *=NONE;
			ACL = UPDATE=SCBxC030, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NEVER, PIN-RESET=CHV16, ADMIN=NEVER, READ=NEVER;
			file-id = 0020;
			size	= 10;
			type	= internal-ef;
			structure = 8;
			content = "81083131313131313131";
			prop-attr = "80010000A0040A00000000001010";
		}

		EF Athena-TransportPIN2 {
			ACL = *=NONE;
			ACL = UPDATE=NEVER, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NONE, PIN-RESET=NONE, ADMIN=NEVER, READ=NONE;
			file-id = 0002;
			size	= 16;
			type	= internal-ef;
			structure = 8;
			content = "81064C415345522B";   #  "LASER+"
			prop-attr = "800100003004100000000000FFFF";
		}

		EF Athena-LogcalExpr-AdminOrUser {
			ACL = *=NONE;
			ACL = UPDATE=NEVER, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NONE, PIN-RESET=NONE, ADMIN=NEVER, READ=NONE;
			file-id = 0030;
			type	= internal-ef;
			structure = 8;
			content = "8112E31089020010890200208902002388008800";
			prop-attr = "00010F00A3";
		}

		EF Athena-LogcalExpr-AdminOrUserOrTransport {
			ACL = *=NONE;
			ACL = UPDATE=NEVER, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NONE, PIN-RESET=NONE, ADMIN=NEVER, READ=NONE;
			file-id = 0032;
			type	= internal-ef;
			structure = 8;
			content = "8118E31689020010890200208902002389020002880088008800";
			prop-attr = "00010F00A3";
		}

		EF Athena-LogcalExpr-AdminOrUserPIN {
			ACL = *=NONE;
			ACL = UPDATE=NEVER, CRYPTO=NONE, DELETE-SELF=CHV16, GENERATE=NONE, PIN-RESET=NONE, ADMIN=NEVER, READ=NONE;
			file-id = 0035;
			type	= internal-ef;
			structure = 8;
			content = "810CE30A89020010890200208800";
			prop-attr = "00010F00A3";
		}

		EF Athena-UserPinType   {
			ACL = *=NONE;
			file-id	= 1000;
			aid = 56:65:72:69:66:69:63:61:74:69:6f:6e;
			size = 1;
		}

		DF Athena-AppDF {
			ACL = *=NONE;
			ACL = CREATE-EF=CHV16, CREATE-DF=CHV16, DELETE-SELF=CHV16, ADMIN=NEVER, ACTIVATE=NONE, DEACTIVATE=CHV16;
			file-id		= 3000;
			aid = 41:53:45:50:4b:43:53;
			size = 40;

			DF private-DF {
				ACL = *=NEVER;
				ACL = CREATE=CHV32, DELETE=NONE, DELETE-SELF=NONE;
				file-id	= 3002;
				aid	= 50:52:49:56:41:54:45;
				size	= 40;

				# Private RSA keys
				EF laser-private-key-attributes   {
					ACL	= WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=CHV32;
					file-id	= 0200;
				}
				EF template-private-key {
					file-id	= 0040;		# Private Exchange key appear in cmapfile
					type	= internal-ef;
					ACL	= *=NEVER;
					ACL	= DELETE-SELF=NONE;
					ACL	= READ=NONE, UPDATE=CHV32, GENERATE=CHV32, PIN-RESET=CHV32, CRYPTO=CHV32;
				}
			}

			DF public-DF {
				ACL = *=NEVER;
				ACL = CREATE=NONE, DELETE=NONE, DELETE-SELF=NONE;
				file-id	= 3001;
				aid	= 50:55:42:4c:49:43;
				size	= 80;

				# Certificate
				EF laser-certificate-attributes  {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=CHV32;
					file-id	= 8440;		# Certificate object
				}

				# Certificate with private key
				EF laser-cmap-certificate-attributes  {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=CHV32;
					file-id	= 8400;		# Certificate object appear in cmapfile
				}

				#Public Key
				EF laser-public-key-attributes {
					ACL = WRITE=CHV32, UPDATE=CHV32, READ=NONE, DELETE-SELF=CHV32;
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

			DF MiniDriver-DF {
				ACL = *=NEVER;
				ACL = CREATE=CHV32, DELETE=NONE, DELETE-SELF=NONE;
				file-id	= 3003;
				aid	= 4d:44;
				size	= 40;

				EF laser-md-cardapps {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, DELETE-SELF=NONE;
					file-id	= 4002;
					aid = 63:61:72:64:61:70:70:73;
				}

				EF laser-md-cardcf {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, DELETE-SELF=NONE;
					file-id	= 4001;
					aid = 63:61:72:64:63:66;
				}

				EF laser-md-cardid {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, DELETE-SELF=NONE;
					file-id	= 4000;
					aid = 63:61:72:64:69:64;
				}

				DF MiniDriver-mscp {
					ACL = *=NEVER;
					ACL = CREATE=CHV32, DELETE=NONE, DELETE-SELF=NONE;
					file-id	= 3005;
					aid = 63:61:72:64:63 66;
				}
			}

				# Private RSA keys
			EF Athena-UserHist   {
				ACL = *=NONE;
				file-id	= B000;
				aid = 55:73:65:72:48:69:73:74;
				size = 26;
			}

			EF Athena-EEED   {
				ACL = *=NONE;
				file-id	= EEED;
				aid = 45:45:45:44;
				size = 4;
			}

			EF Athena-EEEF   {
				ACL = *=NONE;
				file-id	= EEED;
				aid = 45:45:45:46;
				size = 15;
			}

			EF Athena-EEEE   {
				ACL = *=NONE;
				file-id	= EEEE;
				aid = 45:45:45:45;
				size = 173;
			}

			EF Athena-token-info {
				ACL	= WRITE=CHV4, UPDATE=CHV4, READ=NONE, ERASE=NEVER;
				file-id	= C000;
				aid = 54:6f:6b:65:6e:49:6e:66::6f;
				size	= 36;
			}
		}
	}
}
