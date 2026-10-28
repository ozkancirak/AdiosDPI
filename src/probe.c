/*
 * Finds out which preset opens a site on the current connection.
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include "dnsredir.h"
#include "probe.h"

#define START_WAIT_MS 3000
#define STOP_WAIT_MS 5000

static const struct {
    const char *label;
    const char *args;       /* NULL: no tool at all */
} candidates[] = {
    {"no tool",       NULL},
    {"--preset dns",  "--preset dns"},
    {"--preset dns-5", "--preset dns-5"},
    {"--preset dns-9", "--preset dns-9"},
};
#define CANDIDATE_COUNT (sizeof(candidates) / sizeof(*candidates))

/* A real HTTPS request: DNS, TCP and TLS must all work, and the certificate must match. */
static int https_reachable(const char *domain)
{
    wchar_t host[256];
    HINTERNET session, conn, req;
    int ok = 0;

    if (!MultiByteToWideChar(CP_UTF8, 0, domain, -1, host, 256))
        return 0;
    session = WinHttpOpen(L"AdiosDPI", WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return 0;
    WinHttpSetTimeouts(session, 5000, 5000, 5000, 8000);
    conn = WinHttpConnect(session, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (conn) {
        req = WinHttpOpenRequest(conn, L"HEAD", L"/", NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (req) {
            ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                 WinHttpReceiveResponse(req, NULL);
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    }
    WinHttpCloseHandle(session);
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
