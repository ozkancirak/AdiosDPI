/*
 * Detects other programs that use WinDivert, so two of them are not run at once
 * by accident.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "drvcheck.h"

int other_windivert_user(char *name, size_t size)
{
    PROCESSENTRY32 pe;
    HANDLE procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD self = GetCurrentProcessId();
    BOOL more;
    int found = 0;

    if (procs == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    for (more = Process32First(procs, &pe); more && !found; more = Process32Next(procs, &pe)) {
        MODULEENTRY32 me;
        HANDLE mods;
        BOOL next;

        if (pe.th32ProcessID == self || pe.th32ProcessID == 0)
            continue;
        /* Fails for protected processes; those are not bypass tools. */
        mods = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
        if (mods == INVALID_HANDLE_VALUE)
            continue;
        me.dwSize = sizeof(me);
        for (next = Module32First(mods, &me); next; next = Module32Next(mods, &me)) {
            if (_strnicmp(me.szModule, "WinDivert", 9) == 0) {
                snprintf(name, size, "%s", pe.szExeFile);
                found = 1;
                break;
            }
        }
        CloseHandle(mods);
    }
    CloseHandle(procs);
    return found;
}
