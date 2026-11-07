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

#undef LAZY_BCRYPT
#define LAZY_USER32(name) LAZY_LOAD(mod, api, ok, name)

const struct user32_api *user32_api(void) {
    static struct user32_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("user32.dll");
    if (!mod)
        return NULL;
    USER32_FUNCS(LAZY_USER32)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}

#undef LAZY_USER32
#define LAZY_GDI32(name) LAZY_LOAD(mod, api, ok, name)

const struct gdi32_api *gdi32_api(void) {
    static struct gdi32_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("gdi32.dll");
    if (!mod)
        return NULL;
    GDI32_FUNCS(LAZY_GDI32)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}

#undef LAZY_GDI32
#define LAZY_DWMAPI(name) LAZY_LOAD(mod, api, ok, name)

const struct dwmapi_api *dwmapi_api(void) {
    static struct dwmapi_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("dwmapi.dll");
    if (!mod)
        return NULL;
    DWMAPI_FUNCS(LAZY_DWMAPI)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}

#undef LAZY_DWMAPI
#define LAZY_UXTHEME(name) LAZY_LOAD(mod, api, ok, name)

const struct uxtheme_api *uxtheme_api(void) {
    static struct uxtheme_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("uxtheme.dll");
    if (!mod)
        return NULL;
    UXTHEME_FUNCS(LAZY_UXTHEME)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}

#undef LAZY_UXTHEME
#define LAZY_COMCTL32(name) LAZY_LOAD(mod, api, ok, name)

const struct comctl32_api *comctl32_api(void) {
    static struct comctl32_api api;
    static int state;
    HMODULE mod;
    int ok = 1;

    if (state)
        return state > 0 ? &api : NULL;
    state = -1;
    mod = load_system_dll("comctl32.dll");
    if (!mod)
        return NULL;
    COMCTL32_FUNCS(LAZY_COMCTL32)
    if (ok)
        state = 1;
    return ok ? &api : NULL;
}
