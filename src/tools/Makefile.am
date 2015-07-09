include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-tools.rc
EXTRA_DIST = Makefile.mak versioninfo-tools.rc.in

noinst_HEADERS = util.h
bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	pkcs11-tool iasecc-tool
if ENABLE_OPENSSL
bin_PROGRAMS += pkcs15-init
endif

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src
LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

opensc_tool_SOURCES = opensc-tool.c util.c
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = $(OPTIONAL_READLINE_LIBS)
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs11_tool_SOURCES = pkcs11-tool.c util.c
pkcs11_tool_LDADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(OPTIONAL_OPENSSL_LIBS)
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs15_init_SOURCES = pkcs15-init.c util.c
pkcs15_init_LDADD = $(OPTIONAL_OPENSSL_LIBS)
iasecc_tool_SOURCES = iasecc-tool.c util.c
iasecc_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)

if WIN32
opensc_tool_SOURCES += versioninfo-tools.rc
opensc_explorer_SOURCES += versioninfo-tools.rc
pkcs15_tool_SOURCES += versioninfo-tools.rc
pkcs11_tool_SOURCES += versioninfo-tools.rc
pkcs15_crypt_SOURCES += versioninfo-tools.rc
pkcs15_init_SOURCES += versioninfo-tools.rc
iasecc_tool_SOURCES += versioninfo-tools.rc
endif
