/*
 * Finds out which preset opens a site on the current connection.
 */

#include <windows.h>
#include "lazydll.h"
#include <stdio.h>
#include <string.h>
#include "dnsredir.h"
#include "probe.h"

#define START_WAIT_MS 3000
#define STOP_WAIT_MS 5000

/*
 * Least intrusive first. The fixed TTL variants are mode -5 with a fake packet
 * that dies after N hops: the right N depends on how far away the ISP's DPI is,
 * so the probe measures it instead of guessing one number for everybody.
 */
#define MODE5 "-f 2 -e 2 --reverse-frag --max-payload"
static const struct {
    const char *label;
    const char *args;       /* NULL: no tool at all */
} candidates[] = {
    {"no tool",            NULL},
    {"dns",                "--preset dns"},
    {"mode -5",            "-5"},
    {"mode -9",            "-9"},
    {"dns + mode -5",      "--preset dns-5"},
    {"dns + mode -9",      "--preset dns-9"},
    {"dns + ttl 3",        "--preset dns " MODE5 " --set-ttl 3"},
    {"dns + ttl 4",        "--preset dns " MODE5 " --set-ttl 4"},
    {"dns + ttl 5",        "--preset dns " MODE5 " --set-ttl 5"},
    {"dns + ttl 6",        "--preset dns " MODE5 " --set-ttl 6"},
};
#define CANDIDATE_COUNT (sizeof(candidates) / sizeof(*candidates))

/* A real HTTPS request: DNS, TCP and TLS must all work, and the certificate must match. */
static int https_reachable(const char *domain)
{
    wchar_t host[256];
    HINTERNET session, conn, req;
    const struct winhttp_api *w = winhttp_api();
    int ok = 0;

    if (!w || !MultiByteToWideChar(CP_UTF8, 0, domain, -1, host, 256))
        return 0;
    session = w->WinHttpOpen(L"AdiosDPI", WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return 0;
    w->WinHttpSetTimeouts(session, 5000, 5000, 5000, 8000);
    conn = w->WinHttpConnect(session, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (conn) {
        req = w->WinHttpOpenRequest(conn, L"HEAD", L"/", NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (req) {
            ok = w->WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                 w->WinHttpReceiveResponse(req, NULL);
            w->WinHttpCloseHandle(req);
        }
        w->WinHttpCloseHandle(conn);
    }
    w->WinHttpCloseHandle(session);
    return ok;
}

/*
 * Starts this program with args as a child that dies with the returned job, so
 * nothing is left running if the probe itself is stopped. Returns NULL on failure.
 */
static HANDLE start_child(const char *args, HANDLE *process)
{
    char path[MAX_PATH], cmd[MAX_PATH + 64];
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE job;

    if (!GetModuleFileName(NULL, path, sizeof(path)))
        return NULL;
    snprintf(cmd, sizeof(cmd), "\"%s\" %s", path, args);
    job = CreateJobObject(NULL, NULL);
    if (!job)
        return NULL;
    memset(&limit, 0, sizeof(limit));
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limit, sizeof(limit));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(job);
        return NULL;
    }
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    *process = pi.hProcess;
    return job;
}

int probe(const char *domain)
{
    size_t i;

    printf("Probing https://%s/ (each candidate takes a few seconds)\n", domain);
    for (i = 0; i < CANDIDATE_COUNT; i++) {
        HANDLE job = NULL, process = NULL;
        int ok;

        printf("  %-16s ", candidates[i].label);
        fflush(stdout);
        if (candidates[i].args) {
            job = start_child(candidates[i].args, &process);
            if (!job) {
                puts("can't start");
                continue;
            }
            WaitForSingleObject(process, START_WAIT_MS);
            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
                puts("stopped right after starting (is another WinDivert tool running?)");
                CloseHandle(process);
                CloseHandle(job);
                continue;
            }
        }
        flush_dns_cache();
        ok = https_reachable(domain);
        puts(ok ? "opens" : "does not open");
        if (job) {
            CloseHandle(job);               /* kills the child */
            WaitForSingleObject(process, STOP_WAIT_MS);
            CloseHandle(process);
        }
        if (ok) {
            if (candidates[i].args)
                printf("\nUse: adiosdpi.exe %s\n", candidates[i].args);
            else
                puts("\nThe site opens without any tool on this connection.");
            return 0;
        }
    }
    puts("\nNone of the candidates opened the site. It may be blocked in a way these\n"
         "presets do not handle, or it may be down.");
    return 1;
}
