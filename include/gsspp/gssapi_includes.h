#ifndef __GSSPP_GSSAPI_INCLUDES_H__
#define __GSSPP_GSSAPI_INCLUDES_H__

#ifdef __APPLE__

// on macOS, <gssapi.h> and Kerberos frameworks are deprecated in favor of GSS framework.
#include <GSS/GSS.h>

#else

#include <gssapi.h>

#endif

#endif //__GSSPP_GSSAPI_INCLUDES_H__
