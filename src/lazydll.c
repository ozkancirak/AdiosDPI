/*
 * Loads WinHTTP and CNG on first use instead of at program start (see lazydll.h).
 */

#include <stdio.h>
#include <string.h>
#include "lazydll.h"

typedef void (*any_fn)(void);

/* From the system folder only, so a file with the same name next to the program or in the
 * current folder is never picked up. */
static HMODULE load_system_dll(const char *dll) {
    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, sizeof(path));

    if (!n || n + strlen(dll) + 2 > sizeof(path))
        return NULL;
    snprintf(path + n, sizeof(path) - n, "\\%s", dll);
    return LoadLibraryA(path);
}

#define LAZY_LOAD(mod, api, ok, name) \
    ok &= ((api).name = (__typeof__(&name))(any_fn)GetProcAddress(mod, #name)) != NULL;
#define LAZY_WINHTTP(name) LAZY_LOAD(mod, api, ok, name)

const struct winhttp_api *winhttp_api(void) {
    static struct winhttp_api api;
    static int state;           /* 0: not tried yet, 1: loaded, -1: not available */
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("winhttp.dll");
    if (!mod)
        return NULL;
    WINHTTP_FUNCS(LAZY_WINHTTP)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}

#undef LAZY_WINHTTP
#define LAZY_BCRYPT(name) LAZY_LOAD(mod, api, ok, name)

const struct bcrypt_api *bcrypt_api(void) {
    static struct bcrypt_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("bcrypt.dll");
    if (!mod)
        return NULL;
    BCRYPT_FUNCS(LAZY_BCRYPT)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}
