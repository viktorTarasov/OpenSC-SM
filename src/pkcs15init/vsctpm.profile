#
# PKCS15 r/w profile for SmartCard-HSM cards
#
cardinfo {
    label               = "Virtual SmartCard on TPM";
    manufacturer        = "OpenTrust";

    max-pin-length      = 16;
    min-pin-length      = 8;
    pin-encoding        = ascii-numeric;
}

# Default settings.
# This option block will always be processed.
option default {
	macros {
		protected	= *=$PIN, READ=NONE;
		unprotected	= *=NONE;
		so-pin-flags	= local, initialized, soPin;
		so-min-pin-length = 8;
		so-pin-attempts	= 3;
		so-auth-id	= 3;
		odf-size	= 256;
		aodf-size	= 256;
		cdf-size	= 512;
		prkdf-size	= 256;
		pukdf-size	= 256;
		dodf-size	= 256;
	}
}

filesystem {
	DF MF {
		path	= 3F00;
		type	= DF;

		# This is the DIR file
		EF DIR {
			type	= EF;
			file-id	= 2F00;
			acl		= *=NONE;
		}

		# Here comes the application DF
		DF PKCS15-AppDF {
			type	= DF;
			exclusive-aid = A0:00:00:03:97:42:54:46:59;
			acl		= *=NONE;

			EF PKCS15-TokenInfo {
				ACL		= $unprotected;
			}

			EF PKCS15-PrKDF {
				size		= $prkdf-size;
				acl		= $protected;
			}

			EF PKCS15-PuKDF {
				size		= $pukdf-size;
				acl		= $protected;
			}

			EF PKCS15-CDF {
				acl		= $unprotected;
			}
		}
	}
}
