#ifndef _LAZYDLL_H
#define _LAZYDLL_H

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

/*
 * WinHTTP and CNG are only needed by --dns-check, --probe and --fake-quic. They are loaded from
 * the system folder the first time one of those runs, so a normal run does not map two more DLLs
 * (and what they depend on) into memory for nothing.
 */

#define WINHTTP_FUNCS(X) \
    X(WinHttpOpen) X(WinHttpSetTimeouts) X(WinHttpConnect) X(WinHttpOpenRequest) X(WinHttpSendRequest) \
    X(WinHttpReceiveResponse) X(WinHttpQueryHeaders) X(WinHttpReadData) X(WinHttpCloseHandle)

#define BCRYPT_FUNCS(X) \
    X(BCryptOpenAlgorithmProvider) X(BCryptCloseAlgorithmProvider) X(BCryptSetProperty) \
    X(BCryptGenerateSymmetricKey) X(BCryptEncrypt) X(BCryptDestroyKey) X(BCryptCreateHash) \
    X(BCryptHashData) X(BCryptFinishHash) X(BCryptDestroyHash) X(BCryptGenRandom)

#define LAZY_MEMBER(name) __typeof__(&name) name;

struct winhttp_api { WINHTTP_FUNCS(LAZY_MEMBER) };
struct bcrypt_api { BCRYPT_FUNCS(LAZY_MEMBER) };

/* The functions of the DLL, or NULL when it (or one of them) is missing. Loaded once. */
const struct winhttp_api *winhttp_api(void);
const struct bcrypt_api *bcrypt_api(void);

#endif
