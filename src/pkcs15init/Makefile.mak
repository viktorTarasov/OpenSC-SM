TOPDIR = ..\..

TARGET = pkcs15init.lib
OBJECTS = pkcs15-lib.obj profile.obj \
          pkcs15-iasecc.obj

all: $(TARGET)

$(TARGET): $(OBJECTS)
	lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

