TOPDIR = ..\..

TARGET                  = opensc.dll opensc_a.lib
OBJECTS			= \
	sc.obj ctx.obj log.obj errors.obj \
	asn1.obj base64.obj sec.obj card.obj iso7816.obj dir.obj ef-atr.obj padding.obj apdu.obj \
	\
	pkcs15.obj pkcs15-cert.obj pkcs15-data.obj pkcs15-pin.obj \
	pkcs15-prkey.obj pkcs15-pubkey.obj pkcs15-skey.obj \
	pkcs15-sec.obj pkcs15-algo.obj pkcs15-cache.obj pkcs15-syn.obj \
	\
	muscle.obj muscle-filesystem.obj \
	\
	ctbcs.obj reader-ctapi.obj reader-pcsc.obj reader-openct.obj \
	\
	card-default.obj \
	card-iasecc.obj iasecc-sdo.obj iasecc-sm.obj \
	vsctpm-md.obj card-vsctpm.obj \
	\
	pkcs15-vsctpm.obj \
	p15card-helper.obj sm.obj \
	$(TOPDIR)\win32\versioninfo.res

all: $(TOPDIR)\win32\versioninfo.res $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

opensc.dll: $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib ..\common\libscdl.lib ..\pkcs15init\pkcs15init.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type lib$*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:opensc.dll $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib ..\common\libscdl.lib ..\pkcs15init\pkcs15init.lib $(OPENSSL_LIB) $(ZLIB_LIB) gdi32.lib advapi32.lib ws2_32.lib
	if EXIST opensc.dll.manifest mt -manifest opensc.dll.manifest -outputresource:opensc.dll;2

opensc_a.lib: $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib ..\common\libscdl.lib ..\pkcs15init\pkcs15init.lib
	lib $(LIBFLAGS) /out:opensc_a.lib $(OBJECTS) ..\scconf\scconf.lib ..\common\common.lib ..\common\libscdl.lib ..\pkcs15init\pkcs15init.lib $(ZLIB_LIB) user32.lib ws2_32.lib
