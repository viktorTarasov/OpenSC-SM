include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libpkcs15init.la
noinst_HEADERS = profile.h pkcs15-init.h
dist_pkgdata_DATA = \
	pkcs15.profile \
	iasecc.profile \
	ias_adele_admin1.profile ias_adele_admin2.profile ias_adele_common.profile \
	iasecc_generic_pki.profile iasecc_admin_eid.profile \
	vsctpm.profile

AM_CPPFLAGS = -DSC_PKCS15_PROFILE_DIRECTORY=\"$(pkgdatadir)\" -I$(top_srcdir)/src
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS)

libpkcs15init_la_SOURCES = pkcs15-lib.c profile.c pkcs15-iasecc.c pkcs15-vsctpm.c
