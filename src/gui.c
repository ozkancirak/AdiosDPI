/*
 * The window. It does nothing the command line can't do: every action runs this same program
 * with options as a child process and shows what it prints. user32, gdi32 and the other
 * window libraries are loaded here and nowhere else, so the engine and the service never map them.
 */

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "gui.h"
#include "lazydll.h"

#define SERVICE_NAME_W L"AdiosDPI"
#define WM_JOB_DONE (WM_APP + 1)
#define TIMER_REFRESH 1
#define PBM_MARQUEE (WM_USER + 10)

enum { IDC_PANEL = 100, IDC_STATUS, IDC_NOTE, IDC_PROGRESS, IDC_MAIN, IDC_MODE_LABEL, IDC_MODE,
       IDC_SITE_LABEL, IDC_SITE, IDC_INSTALL, IDC_REMOVE, IDC_DETAILS, IDC_LANG, IDC_VERSION, IDC_LOG };
enum { JOB_ENGINE = 1, JOB_FIX, JOB_INSTALL, JOB_REMOVE };
enum { AFTER_NONE, AFTER_START, AFTER_INSTALL };
enum { NOTE_NONE, NOTE_NO_FIX, NOTE_NOT_FOUND, NOTE_BAD_SITE, NOTE_ENGINE_FAILED, NOTE_FOUND };

/* Client size: the compact window, and how much the log adds when it is shown. */
#define WIN_W 400
#define WIN_H 378
#define LOG_H 196

static const struct user32_api *U;
static const struct gdi32_api *G;
static const struct dwmapi_api *D;          /* these three are optional: without them the window stays plain */
static const struct uxtheme_api *X;
static const struct comctl32_api *C;
static HWND win, h_panel, h_status, h_note, h_progress, h_main, h_mode_label, h_mode, h_site_label, h_site,
            h_install, h_remove, h_details, h_lang, h_version, h_log;
static HFONT font, font_bold, font_big;
static HBRUSH brush_bg, brush_field, brush_panel;
static HANDLE job_object, cur_proc;         /* cur_proc: the child that is running, if any */
static int cur_kind, after_fix, stopped, no_fix_needed, note_kind, log_shown;
static int lang;                            /* 0 English, 1 Turkish */
static int dark;                            /* the system's app theme is dark; not a setting of ours */
static int frame_w, frame_h;                /* window size minus client size */
static char found_text[512];                /* what --probe printed after "Use: adiosdpi.exe " */
static const char *version_text = "";

static const char *const presets[] = {"dns", "dns-5", "dns-9", "dns-ttl5", "dns-ttl3", "ttl3"};
#define PRESET_COUNT (sizeof(presets) / sizeof(*presets))

#define DARK_BG RGB(32, 32, 32)
#define DARK_FIELD RGB(45, 45, 45)
#define DARK_PANEL RGB(24, 24, 24)
#define DARK_TEXT RGB(240, 240, 240)
#define DARK_DIM RGB(150, 150, 150)
#define LIGHT_PANEL RGB(226, 226, 226)
#define LIGHT_DIM RGB(100, 100, 100)

/* Turkish letters are written as \u escapes so the file does not depend on its encoding. */
static const wchar_t *T(const wchar_t *en, const wchar_t *tr) {
    return lang ? tr : en;
}

/* Turkish if Windows is shown in Turkish; English for every other language and when it can't be told. */
static int system_is_turkish(void) {
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_TURKISH;
}

static int system_is_dark(void) {
#ifdef FORCE_DARK                           /* only for a test build, to see the dark window without changing Windows */
    return 1;
#else
    DWORD light = 1, size = sizeof(light);

    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                     L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &light, &size) != ERROR_SUCCESS)
        return 0;
    return light == 0;
#endif
}

/* Dark title bar and dark controls when the system says so; the stock look otherwise. */
static void apply_theme(void) {
    HWND all[] = {h_main, h_mode, h_site, h_install, h_remove, h_details, h_lang, h_log};
    BOOL on;
    size_t i;

    dark = system_is_dark();
    on = dark;
    if (D && FAILED(D->DwmSetWindowAttribute(win, 20, &on, sizeof(on))))    /* 20; 19 on early Windows 10 builds */
        D->DwmSetWindowAttribute(win, 19, &on, sizeof(on));
    if (X)
        for (i = 0; i < sizeof(all) / sizeof(*all); i++) {
            const wchar_t *theme = NULL;

            if (dark)
                theme = (all[i] == h_mode || all[i] == h_site || all[i] == h_lang) ? L"DarkMode_CFD" : L"DarkMode_Explorer";
            X->SetWindowTheme(all[i], theme, NULL);
        }
    U->RedrawWindow(win, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

static void log_append(const wchar_t *s) {
    U->SendMessageW(h_log, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    U->SendMessageW(h_log, EM_REPLACESEL, FALSE, (LPARAM)s);
    U->SendMessageW(h_log, EM_SCROLLCARET, 0, 0);
}

/* The log is below the compact window; it opens by itself when something went wrong. */
static void show_log(int show) {
    int h = WIN_H + (show ? LOG_H + 8 : 0) + frame_h;

    log_shown = show;
    U->SetWindowPos(win, NULL, 0, 0, WIN_W + frame_w, h, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    U->SetWindowTextW(h_details, show ? T(L"Hide log", L"Günlüğü gizle") : T(L"Show log", L"Günlüğü göster"));
}

/* 0 not installed, 1 installed and stopped, 2 running */
static int service_state(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), svc;
    SERVICE_STATUS st;
    int state = 0;

    if (!scm)
        return 0;
    svc = OpenServiceW(scm, SERVICE_NAME_W, SERVICE_QUERY_STATUS);
    if (svc) {
        state = 1;
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED)
            state = 2;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return state;
}

/* What the child prints goes to the log; the line that says what worked is remembered. */
static DWORD WINAPI reader(LPVOID param) {
    HANDLE pipe = param;
    char buf[1024], line[sizeof(found_text)];
    wchar_t wide[sizeof(buf)];
    size_t ll = 0;
    DWORD n, i, exit_code = 0;
    static const char use[] = "Use: adiosdpi.exe ";

    while (ReadFile(pipe, buf, sizeof(buf), &n, NULL) && n) {
        size_t w = 0;
        int count;

        for (i = 0; i < n; i++) {
            if (buf[i] == '\n' || buf[i] == '\r' || ll == sizeof(line) - 1) {
                line[ll] = '\0';
                if (strncmp(line, use, sizeof(use) - 1) == 0)
                    snprintf(found_text, sizeof(found_text), "%s", line + sizeof(use) - 1);
                else if (strstr(line, "opens without any tool"))
                    no_fix_needed = 1;
                ll = 0;
            }
            if (buf[i] != '\r' && buf[i] != '\n' && ll < sizeof(line) - 1)
                line[ll++] = buf[i];
        }
        /* the edit control wants \r\n */
        count = MultiByteToWideChar(CP_ACP, 0, buf, (int)n, wide, (int)(sizeof(wide) / sizeof(*wide)));
        if (count > 0) {
            wchar_t out[2 * sizeof(buf) + 2];
            int k;

            for (k = 0; k < count; k++) {
                if (wide[k] == L'\r')
                    continue;
                if (wide[k] == L'\n')
                    out[w++] = L'\r';
                out[w++] = wide[k];
            }
            out[w] = L'\0';
            log_append(out);
        }
    }
    CloseHandle(pipe);
    WaitForSingleObject(cur_proc, INFINITE);
    GetExitCodeProcess(cur_proc, &exit_code);
    U->PostMessageW(win, WM_JOB_DONE, (WPARAM)cur_kind, (LPARAM)exit_code);
    return 0;
}

/* Runs this program with args. The child dies with the window (it is in the job object). */
static int spawn(int kind, const wchar_t *args) {
    wchar_t path[MAX_PATH], cmd[MAX_PATH + 600];
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE rd, wr, t;

    if (cur_proc || !GetModuleFileNameW(NULL, path, MAX_PATH))
        return 0;
    _snwprintf(cmd, sizeof(cmd) / sizeof(*cmd), L"\"%ls\" %ls", path, args);
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return 0;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = si.hStdError = wr;
    si.hStdInput = INVALID_HANDLE_VALUE;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return 0;
    }
    CloseHandle(wr);
    AssignProcessToJobObject(job_object, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    cur_proc = pi.hProcess;
    cur_kind = kind;
    stopped = 0;
    if (kind == JOB_FIX) {
        found_text[0] = '\0';
        no_fix_needed = 0;
    }
    log_append(L"\r\n");
    t = CreateThread(NULL, 0, reader, rd, 0, NULL);
    if (t)
        CloseHandle(t);
    return 1;
}

static int site_valid(const wchar_t *s) {
    size_t i, n = wcslen(s);
    int dot = 0;

    if (n < 3 || n > 253)
        return 0;
    for (i = 0; i < n; i++) {
        if (s[i] == L'.')
            dot = 1;
        else if (!((s[i] >= L'0' && s[i] <= L'9') || (s[i] >= L'a' && s[i] <= L'z') ||
                   (s[i] >= L'A' && s[i] <= L'Z') || s[i] == L'-'))
            return 0;
    }
    return dot;
}

static int mode_index(void) {
    return (int)U->SendMessageW(h_mode, CB_GETCURSEL, 0, 0);
}

/* The options of the chosen mode: what the search found (Automatic) or a preset. */
static void mode_args(wchar_t *out, size_t size) {
    int sel = mode_index();

    if (sel <= 0)
        _snwprintf(out, size, L"%hs", found_text);
    else
        _snwprintf(out, size, L"--preset %hs", presets[(size_t)(sel - 1) < PRESET_COUNT ? sel - 1 : 0]);
}

static const wchar_t *note_text(void) {
    switch (note_kind) {
    case NOTE_NO_FIX:
        return T(L"The site opens without any tool: nothing to fix", L"Site zaten açılıyor: düzeltilecek bir şey yok");
    case NOTE_NOT_FOUND:
        return T(L"Nothing opened the site. See the log", L"Hiçbiri siteyi açmadı. Günlüğe bakın");
    case NOTE_BAD_SITE:
        return T(L"Type a site name such as discord.com", L"discord.com gibi bir site adı yazın");
    case NOTE_ENGINE_FAILED:
        return T(L"It stopped with an error. See the log", L"Hata ile durdu. Günlüğe bakın");
    case NOTE_FOUND:
        return T(L"A setting that opens the site was found", L"Siteyi açan bir ayar bulundu");
    }
    return L"";
}

static void update_ui(void) {
    int svc = service_state();
    int busy = cur_proc != NULL;
    int fixing = busy && cur_kind == JOB_FIX;
    int engine = busy && cur_kind == JOB_ENGINE;
    int automatic = mode_index() <= 0;
    const wchar_t *status, *note = note_text();

    U->EnableWindow(h_main, busy ? (fixing || engine) : svc != 2);
    U->EnableWindow(h_install, !busy && svc == 0);
    U->EnableWindow(h_remove, !busy && svc != 0);
    U->EnableWindow(h_mode, !busy);
    U->EnableWindow(h_site, !busy && automatic);
    U->SetWindowTextW(h_main, (fixing || engine) ? T(L"STOP", L"DURDUR") : T(L"START", L"BAŞLAT"));
    if (h_progress) {
        U->ShowWindow(h_progress, fixing ? SW_SHOW : SW_HIDE);
        U->SendMessageW(h_progress, PBM_MARQUEE, (WPARAM)(fixing != 0), 30);
    }

    if (fixing) {
        status = T(L"SEARCHING...", L"ARANIYOR...");
        note = T(L"Looking for a setting that opens the site", L"Siteyi açan bir ayar aranıyor");
    }
    else if (busy && !engine) {
        status = T(L"WORKING...", L"ÇALIŞILIYOR...");
        note = L"";
    }
    else if (engine) {
        status = T(L"RUNNING", L"ÇALIŞIYOR");
        note = T(L"Stops when this window closes", L"Bu pencere kapanınca durur");
    }
    else if (svc == 2) {
        status = T(L"RUNNING AS A SERVICE", L"SERVİS OLARAK ÇALIŞIYOR");
        note = T(L"Starts with Windows", L"Windows ile başlar");
    }
    else if (svc == 1) {
        status = T(L"SERVICE STOPPED", L"SERVİS DURMUŞ");
        if (!note[0])
            note = T(L"Installed but not running", L"Kurulu ama çalışmıyor");
    }
    else {
        status = T(L"READY", L"HAZIR");
        if (!note[0])
            note = T(L"Press START", L"BAŞLAT'a basın");
    }
    U->SetWindowTextW(h_status, status);
    U->SetWindowTextW(h_note, note);
}

static void apply_language(void) {
    int sel = mode_index();

    U->SetWindowTextW(h_mode_label, T(L"Mode:", L"Mod:"));
    U->SetWindowTextW(h_site_label, T(L"Test site:", L"Test sitesi:"));
    U->SetWindowTextW(h_install, T(L"Install as a service (starts with Windows)", L"Servis olarak kur (Windows ile başlar)"));
    U->SetWindowTextW(h_remove, T(L"Remove the service", L"Servisi kaldır"));
    U->SendMessageW(h_mode, CB_DELETESTRING, 0, 0);
    U->SendMessageW(h_mode, CB_INSERTSTRING, 0, (LPARAM)T(L"Automatic (finds the best)", L"Otomatik (en iyisini bulur)"));
    U->SendMessageW(h_mode, CB_SETCURSEL, (WPARAM)(sel < 0 ? 0 : sel), 0);
    show_log(log_shown);
    update_ui();
}

static HWND make(const wchar_t *cls, DWORD style, DWORD ex, int x, int y, int w, int h, int id, HFONT f) {
    HWND c = U->CreateWindowExW(ex, cls, L"", WS_CHILD | WS_VISIBLE | style, x, y, w, h, win,
                                (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    if (c)
        U->SendMessageW(c, WM_SETFONT, (WPARAM)f, TRUE);
    return c;
}

static void create_controls(void) {
    size_t i;
    wchar_t name[40];
    wchar_t ver[80];

    h_panel = make(L"STATIC", SS_LEFT, 0, 15, 12, 370, 78, IDC_PANEL, font);
    h_status = make(L"STATIC", SS_CENTER, 0, 15, 20, 370, 28, IDC_STATUS, font_big);
    h_note = make(L"STATIC", SS_CENTER, 0, 15, 50, 370, 20, IDC_NOTE, font);
    h_progress = C ? make(L"msctls_progress32", 0x08 /* PBS_MARQUEE */, 0, 15, 76, 370, 10, IDC_PROGRESS, font) : NULL;

    h_main = make(L"BUTTON", BS_PUSHBUTTON | WS_TABSTOP, 0, 50, 104, 300, 52, IDC_MAIN, font_big);

    h_mode_label = make(L"STATIC", SS_LEFT, 0, 50, 176, 110, 20, IDC_MODE_LABEL, font_bold);
    h_mode = make(L"COMBOBOX", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, 0, 165, 172, 185, 220, IDC_MODE, font);
    U->SendMessageW(h_mode, CB_ADDSTRING, 0, (LPARAM)L"-");
    for (i = 0; i < PRESET_COUNT; i++) {
        _snwprintf(name, sizeof(name) / sizeof(*name), L"%hs", presets[i]);
        U->SendMessageW(h_mode, CB_ADDSTRING, 0, (LPARAM)name);
    }
    U->SendMessageW(h_mode, CB_SETCURSEL, 0, 0);

    h_site_label = make(L"STATIC", SS_LEFT, 0, 50, 211, 110, 20, IDC_SITE_LABEL, font_bold);
    h_site = make(L"EDIT", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, 165, 207, 185, 24, IDC_SITE, font);
    U->SetWindowTextW(h_site, L"discord.com");

    h_install = make(L"BUTTON", BS_PUSHBUTTON | WS_TABSTOP, 0, 50, 250, 300, 36, IDC_INSTALL, font_bold);
    h_remove = make(L"BUTTON", BS_PUSHBUTTON | WS_TABSTOP, 0, 50, 294, 300, 36, IDC_REMOVE, font_bold);

    h_details = make(L"BUTTON", BS_PUSHBUTTON | WS_TABSTOP, 0, 50, 336, 140, 24, IDC_DETAILS, font);
    h_lang = make(L"COMBOBOX", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, 0, 255, 336, 95, 120, IDC_LANG, font);
    U->SendMessageW(h_lang, CB_ADDSTRING, 0, (LPARAM)L"English");
    U->SendMessageW(h_lang, CB_ADDSTRING, 0, (LPARAM)L"Türkçe");
    U->SendMessageW(h_lang, CB_SETCURSEL, (WPARAM)lang, 0);

    _snwprintf(ver, sizeof(ver) / sizeof(*ver), L"AdiosDPI %hs", version_text);
    h_version = make(L"STATIC", SS_CENTER, 0, 0, 362, WIN_W, 16, IDC_VERSION, font);
    U->SetWindowTextW(h_version, ver);

    h_log = make(L"EDIT", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, WS_EX_CLIENTEDGE,
                 15, WIN_H + 4, 370, LOG_H, IDC_LOG, font);
    U->SendMessageW(h_log, EM_SETLIMITTEXT, 1 << 20, 0);
}

static void on_job_done(int kind, DWORD exit_code) {
    int had_stop = stopped, next = after_fix;

    CloseHandle(cur_proc);
    cur_proc = NULL;
    cur_kind = 0;
    stopped = 0;
    after_fix = AFTER_NONE;
    note_kind = NOTE_NONE;

    if (kind == JOB_FIX && !had_stop) {
        if (exit_code == 0 && no_fix_needed) {
            note_kind = NOTE_NO_FIX;
        }
        else if (exit_code == 0 && found_text[0]) {
            wchar_t args[700], cmd[720];

            note_kind = NOTE_FOUND;
            mode_args(args, sizeof(args) / sizeof(*args));
            if (next == AFTER_START) {
                note_kind = NOTE_NONE;
                spawn(JOB_ENGINE, args);
            }
            else if (next == AFTER_INSTALL) {
                note_kind = NOTE_NONE;
                _snwprintf(cmd, sizeof(cmd) / sizeof(*cmd), L"--install %ls", args);
                spawn(JOB_INSTALL, cmd);
            }
        }
        else {
            note_kind = NOTE_NOT_FOUND;
            show_log(1);
        }
    }
    else if (kind == JOB_ENGINE && !had_stop && exit_code != 0) {
        note_kind = NOTE_ENGINE_FAILED;
        show_log(1);
    }
    update_ui();
}

/* START with Automatic searches first; the found setting is started (or installed) when the search ends. */
static void begin(int after) {
    wchar_t site[300], args[700];

    note_kind = NOTE_NONE;
    if (mode_index() > 0) {
        mode_args(site, sizeof(site) / sizeof(*site));
        if (after == AFTER_INSTALL)
            _snwprintf(args, sizeof(args) / sizeof(*args), L"--install %ls", site);
        else
            _snwprintf(args, sizeof(args) / sizeof(*args), L"%ls", site);
        spawn(after == AFTER_INSTALL ? JOB_INSTALL : JOB_ENGINE, args);
        update_ui();
        return;
    }
    U->GetWindowTextW(h_site, site, (int)(sizeof(site) / sizeof(*site)));
    if (!site_valid(site)) {
        note_kind = NOTE_BAD_SITE;
        update_ui();
        return;
    }
    _snwprintf(args, sizeof(args) / sizeof(*args), L"--probe %ls", site);
    after_fix = after;
    if (!spawn(JOB_FIX, args))
        after_fix = AFTER_NONE;
    update_ui();
}

static void command(int id, int code) {
    switch (id) {
    case IDC_LANG:
        if (code == CBN_SELCHANGE) {
            lang = (int)U->SendMessageW(h_lang, CB_GETCURSEL, 0, 0) == 1;
            apply_language();
        }
        break;
    case IDC_MODE:
        if (code == CBN_SELCHANGE)
            update_ui();
        break;
    case IDC_MAIN:
        if (cur_proc) {
            stopped = 1;
            after_fix = AFTER_NONE;
            TerminateProcess(cur_proc, 0);
        }
        else {
            begin(AFTER_START);
        }
        break;
    case IDC_INSTALL:
        begin(AFTER_INSTALL);
        break;
    case IDC_REMOVE:
        note_kind = NOTE_NONE;
        if (spawn(JOB_REMOVE, L"--remove"))
            update_ui();
        break;
    case IDC_DETAILS:
        show_log(!log_shown);
        break;
    }
}

static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        win = h;
        create_controls();
        apply_language();
        apply_theme();
        U->SetTimer(h, TIMER_REFRESH, 2000, NULL);
        return 0;
    case WM_SETTINGCHANGE:      /* the user switched the system theme while the window is open */
        if (lp && wcscmp((const wchar_t *)lp, L"ImmersiveColorSet") == 0)
            apply_theme();
        break;
    case WM_ERASEBKGND:
        if (dark) {
            RECT rc;

            U->GetClientRect(h, &rc);
            U->FillRect((HDC)wp, &rc, brush_bg);
            return 1;
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HWND c = (HWND)lp;
        int panel = c == h_panel || c == h_status || c == h_note;
        int field = c == h_log || c == h_site || msg != WM_CTLCOLORSTATIC;
        int dim = c == h_note || c == h_version;

        if (!dark && !panel)
            break;
        G->SetTextColor((HDC)wp, dark ? (dim ? DARK_DIM : DARK_TEXT) : (dim ? LIGHT_DIM : RGB(0, 0, 0)));
        G->SetBkColor((HDC)wp, panel ? (dark ? DARK_PANEL : LIGHT_PANEL) : (dark ? (field ? DARK_FIELD : DARK_BG) : RGB(240, 240, 240)));
        return (LRESULT)(panel ? brush_panel : (field ? brush_field : brush_bg));
    }
    case WM_COMMAND:
        command(LOWORD(wp), HIWORD(wp));
        return 0;
    case WM_TIMER:
        update_ui();
        return 0;
    case WM_JOB_DONE:
        on_job_done((int)wp, (DWORD)lp);
        return 0;
    case WM_CLOSE:
        U->DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        U->PostQuitMessage(0);
        return 0;
    }
    return U->DefWindowProcW(h, msg, wp, lp);
}

/*
 * A stream that goes to a file or a pipe (the window reads its children that way) is kept. Anything
 * else, including the console handles a shell hands down before this process has joined its
 * console, is replaced by the console itself.
 */
static void to_console(DWORD which, FILE *stream, const char *device, const char *mode) {
    HANDLE h = GetStdHandle(which);
    DWORD type = (h != NULL && h != INVALID_HANDLE_VALUE) ? GetFileType(h) : FILE_TYPE_UNKNOWN;

    if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE)
        return;
    if (freopen(device, mode, stream))
        SetStdHandle(which, (HANDLE)_get_osfhandle(_fileno(stream)));
}

int console_attach(void) {
    if (GetConsoleWindow() == NULL && !AttachConsole(ATTACH_PARENT_PROCESS))
        return 0;
    to_console(STD_OUTPUT_HANDLE, stdout, "CONOUT$", "w");
    to_console(STD_ERROR_HANDLE, stderr, "CONOUT$", "w");
    to_console(STD_INPUT_HANDLE, stdin, "CONIN$", "r");
    return 1;
}

int gui_run(const char *version) {
    WNDCLASSEXW wc;
    NONCLIENTMETRICSW ncm;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_PROGRESS_CLASS};
    HINSTANCE inst = GetModuleHandleW(NULL);
    RECT rect = {0, 0, WIN_W, WIN_H};
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    MSG msg;

    version_text = version;
    U = user32_api();
    G = gdi32_api();
    if (!U || !G)
        return 1;
    D = dwmapi_api();
    X = uxtheme_api();
    C = comctl32_api();
    if (C)
        C->InitCommonControlsEx(&icc);
    if (X) {
        /* uxtheme ordinal 135, SetPreferredAppMode(AllowDark): there is no named export; without it the dark button theme draws a white frame. */
        HMODULE ux = GetModuleHandleW(L"uxtheme.dll");
        typedef int (WINAPI *set_app_mode_fn)(int);
        FARPROC fn = ux ? GetProcAddress(ux, MAKEINTRESOURCEA(135)) : NULL;

        if (fn)
            ((set_app_mode_fn)(void (*)(void))fn)(1);
    }
    lang = system_is_turkish();
    brush_bg = G->CreateSolidBrush(DARK_BG);
    brush_field = G->CreateSolidBrush(DARK_FIELD);
    brush_panel = G->CreateSolidBrush(system_is_dark() ? DARK_PANEL : LIGHT_PANEL);

    job_object = CreateJobObjectW(NULL, NULL);
    memset(&limit, 0, sizeof(limit));
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job_object)
        SetInformationJobObject(job_object, JobObjectExtendedLimitInformation, &limit, sizeof(limit));

    memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (U->SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        font = G->CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfWeight = FW_BOLD;
        font_bold = G->CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfHeight = ncm.lfMessageFont.lfHeight * 5 / 4;
        font_big = G->CreateFontIndirectW(&ncm.lfMessageFont);
    }

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hIcon = U->LoadIconW(inst, L"id");
    wc.hCursor = U->LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"AdiosDPIWindow";
    if (!U->RegisterClassExW(&wc))
        return 1;
    U->AdjustWindowRectEx(&rect, style, FALSE, 0);
    frame_w = (rect.right - rect.left) - WIN_W;
    frame_h = (rect.bottom - rect.top) - WIN_H;
    if (!U->CreateWindowExW(0, wc.lpszClassName, L"AdiosDPI", style, CW_USEDEFAULT, CW_USEDEFAULT,
                            rect.right - rect.left, rect.bottom - rect.top, NULL, NULL, inst, NULL))
        return 1;
    U->ShowWindow(win, SW_SHOWNORMAL);

    while (U->GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!U->IsDialogMessageW(win, &msg)) {
            U->TranslateMessage(&msg);
            U->DispatchMessageW(&msg);
        }
    }
    if (job_object)
        CloseHandle(job_object);            /* ends the children that are still running */
    G->DeleteObject(font);
    G->DeleteObject(font_bold);
    G->DeleteObject(font_big);
    G->DeleteObject(brush_bg);
    G->DeleteObject(brush_field);
    G->DeleteObject(brush_panel);
    return 0;
}
