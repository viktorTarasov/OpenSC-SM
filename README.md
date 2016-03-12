# opensc


Description<br>
D language: A ("Deimos"-) binding to libopensc (reduced extend required for external modules [driver/SM])

System dependency: libopensc  [https://github.com/OpenSC/OpenSC/wiki]

OpenSC allows for loading smart card specific code from shared objects/DLLs, if opensc.conf is configured accordingly.

Naming of identifiers (types etc.): As far as possible identical to the C source code, except where D language reserved keywords/identifiers are involved, and
except where constructs like
typedef struct abcde {...} abcde_t;
where encountered.
In the former case, a trailing underscore was added,
in the latter case, most of types abcde_t are gone and named abcde only.

Usage example: My project https://github.com/carblue/acos5_64
