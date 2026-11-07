#ifndef _LAZYDLL_H
#define _LAZYDLL_H

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>

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

/* The window (gui.c) is only built when the program is started by a double click. */
#define USER32_FUNCS(X)     X(RegisterClassExW) X(CreateWindowExW) X(DefWindowProcW) X(GetMessageW) X(TranslateMessage)     X(DispatchMessageW) X(PostQuitMessage) X(SendMessageW) X(PostMessageW) X(SetWindowTextW)     X(GetWindowTextW) X(EnableWindow) X(ShowWindow) X(LoadCursorW) X(LoadIconW) X(DestroyWindow)     X(SetTimer) X(IsDialogMessageW) X(GetSystemMetrics) X(SystemParametersInfoW) X(AdjustWindowRectEx) X(SetWindowPos) X(FillRect) X(GetClientRect) X(RedrawWindow)

#define GDI32_FUNCS(X)     X(CreateFontIndirectW) X(DeleteObject) X(CreateSolidBrush) X(SetTextColor) X(SetBkColor)

#define COMCTL32_FUNCS(X) X(InitCommonControlsEx)
#define DWMAPI_FUNCS(X) X(DwmSetWindowAttribute)
#define UXTHEME_FUNCS(X) X(SetWindowTheme)

#define LAZY_MEMBER(name) __typeof__(&name) name;

struct winhttp_api { WINHTTP_FUNCS(LAZY_MEMBER) };
struct bcrypt_api { BCRYPT_FUNCS(LAZY_MEMBER) };
struct user32_api { USER32_FUNCS(LAZY_MEMBER) };
struct gdi32_api { GDI32_FUNCS(LAZY_MEMBER) };
struct comctl32_api { COMCTL32_FUNCS(LAZY_MEMBER) };
struct dwmapi_api { DWMAPI_FUNCS(LAZY_MEMBER) };
struct uxtheme_api { UXTHEME_FUNCS(LAZY_MEMBER) };

/* The functions of the DLL, or NULL when it (or one of them) is missing. Loaded once. */
const struct winhttp_api *winhttp_api(void);
const struct bcrypt_api *bcrypt_api(void);
const struct user32_api *user32_api(void);
const struct gdi32_api *gdi32_api(void);
const struct comctl32_api *comctl32_api(void);
const struct dwmapi_api *dwmapi_api(void);
const struct uxtheme_api *uxtheme_api(void);

#endif
