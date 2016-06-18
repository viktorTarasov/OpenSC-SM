.lib and .dll file from:
https://download.libsodium.org/libsodium/releases/libsodium-1.0.10-msvc.zip

folder ...\libsodium-1.0.10-msvc\x64\Release\v140\dynamic

libsodium.lib renamed to sodium.lib

https://adrianhenke.wordpress.com/2008/12/05/create-lib-file-from-dll/

dumpbin /exports C:\yourpath\yourlib.dll > out.txt
bereits beschafftes opensc.def benutzt

C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin>lib /def:C:\Users\Han
s-Carsten\AppData\Roaming\dub\packages\opensc-master\lib\opensc.def /OUT:C:\bin\
opensc.lib /MACHINE:X64
Microsoft (R) Library Manager Version 14.00.23506.0
Copyright (C) Microsoft Corporation.  All rights reserved.

   Bibliothek "C:\bin\opensc.lib" und Objekt "C:\bin\opensc.exp" werden erstellt
.

C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin>