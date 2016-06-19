# opensc


D language: Deimos-like binding to libopensc, current C-source version 0.16.0, released June 2016

The OpenSC framework allows for providing e.g. a smart card driver (or Secure Messaging module) as external shared object/DLL, if opensc.conf is configured accordingly.
This binding allows to implement in the D programming language.

Not all opensc header content is covered, but what is required/usefull for external modules (smart card driver/SM).
There is a small, undisturbing deviation concerning cards.h/cards.d: SC_CARD_TYPE_ACOS5... where the driver, I'm implementing, is involved.

There was an incompatible API change from version 0.15.0 to version 0.16.0, that hit pkcs15.h/pkcs15.d: Since, code using this binding has to tell at compile time, whether it's going to be
linked against a libopensc binary upto version 0.15.0, or the latest version 0.16.0. As of now, this is managed by the version identifier FAKE_OPENSC_VERSION too.
I've no clue, if it's possible to automate this, but if I understood CTFE, then it's not, thus FAKE_OPENSC_VERSION has to be adjusted manually appropriately in external module's dub.json file.
I'm not going to investigate API's below 0.15.0 and if they require special handling within my binding. In other words, You are save only with release binary versions>=0.15.0 (which is available e.g.
in Ubuntu since wily 15.10). The OpenSC project has done another crazy thing: Publishing different release source code under the same version number: Code of version 0.15.0  downloaded in 2015 is different
from what You can download now as opensc-0.15.0.tar.gz; thus I even can't know which version 0.15.0 was picked by package maintainers; I'm refering to a version 0.15.0 dated 2015-05-16;

REMINDER:
The opensc framework binary implicitely knows it's own version and can report it (let's assume, the package was built from C-source version 0.15.0, thus version string is "0.15.0").
The same applies to an external module (e.g. my module acos5_64 knows it's internal version string, which currently is "0.16.0", meaning that it can deal with all opensc framework versions upto "0.16.0", and can/must be able to report this value).
After a successfull dlopen of an external module, the opensc framework checks for matching version strings (opensc framework <-> external module) and rejects the external module in case of mismatch,
otherwise it reports (if enabled) to the /tmp/opensc-debug.log file: successfully loaded card driver 'acos5_64'.
Without further provisions, driver acos5_64 will be rejected in this example. This is where the version identifier FAKE_OPENSC_VERSION first came into play. When set during build of the external module, it
will cause the external module acos5_64 to report/mirror the opensc framework version, not its own version. As side effect in this special example case, a set FAKE_OPENSC_VERSION implies for this binding,
that the API of (max.) version 0.15.0 has to be exposed during compilation.

System dependency: libopensc.so.3  [https://github.com/OpenSC/OpenSC/wiki], which in turn depends on openssl
