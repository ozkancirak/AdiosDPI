/*
 * Detects other programs that use WinDivert, so two of them are not run at once
 * by accident.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "drvcheck.h"

int windivert_users(char *names, size_t size, DWORD skip_pid)
{
    PROCESSENTRY32 pe;
    HANDLE procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD self = GetCurrentProcessId();
    BOOL more;
    int count = 0;

    if (size)
        names[0] = '\0';
    if (procs == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    for (more = Process32First(procs, &pe); more; more = Process32Next(procs, &pe)) {
        MODULEENTRY32 me;
        HANDLE mods;
        BOOL next;

        if (pe.th32ProcessID == self || pe.th32ProcessID == 0 ||
            (skip_pid && pe.th32ProcessID == skip_pid))
            continue;
        /* Fails for protected processes; those are not bypass tools. */
        mods = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
        if (mods == INVALID_HANDLE_VALUE)
            continue;
        me.dwSize = sizeof(me);
        for (next = Module32First(mods, &me); next; next = Module32Next(mods, &me)) {
            if (_strnicmp(me.szModule, "WinDivert", 9) == 0) {
                size_t used = strlen(names);
                if (used + strlen(pe.szExeFile) + 3 < size)
                    snprintf(names + used, size - used, "%s%s", count ? ", " : "", pe.szExeFile);
                count++;
                break;
            }
        }
        CloseHandle(mods);
    }
    CloseHandle(procs);
    return count;
}
