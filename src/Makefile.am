MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

# Order IS important
SUBDIRS = common scconf

if ENABLE_SM
SUBDIRS += libsm
endif

SUBDIRS += pkcs15init libopensc pkcs11 \
	tools tests minidriver

if ENABLE_SM
SUBDIRS += smm
endif

