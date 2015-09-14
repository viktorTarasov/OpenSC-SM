set OPENSC_VSCTPM_PATH=e:\OpenSC-VSCTPM\

call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86

cd %OPENSC_VSCTPM_PATH%opentrust-opensc-vsctpm
nmake /f Makefile.mak BUILD_ON=WIN64 OPENSSL_BUILD=OPENTRUST

cd %OPENSC_VSCTPM_PATH%
rmdir /S /Q build
mkdir build
copy opentrust-opensc-vsctpm\src\pkcs15init\pkcs15.profile .\build\
copy opentrust-opensc-vsctpm\src\pkcs15init\vsctpm.profile .\build\
copy opentrust-opensc-vsctpm\src\pkcs11\opensc-pkcs11.dll .\build\
copy opentrust-opensc-vsctpm\etc\opensc.conf.win .\build\opensc.conf
