/*
 * Detects other programs that use WinDivert, so two of them are not run at once
 * by accident.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "drvcheck.h"

static BOOL find_process(HANDLE procs, DWORD pid, PROCESSENTRY32 *pe)
{
    BOOL more;

    pe->dwSize = sizeof(*pe);
    for (more = Process32First(procs, pe); more; more = Process32Next(procs, pe))
        if (pe->th32ProcessID == pid)
            return TRUE;
    return FALSE;
}

int windivert_users(char *names, size_t size, DWORD skip_pid)
{
    PROCESSENTRY32 pe;
    HANDLE procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD self = GetCurrentProcessId(), ancestors[8], cur = self;
    char self_name[MAX_PATH] = "";
    BOOL more;
    int count = 0, ancestor_count = 0, i;

    if (size)
        names[0] = '\0';
    if (procs == INVALID_HANDLE_VALUE)
        return 0;
    /*
     * The window and --probe start this program as a child, and both have the WinDivert library
     * loaded: the copies of this program that started us are not another tool.
     */
    if (find_process(procs, self, &pe))
        snprintf(self_name, sizeof(self_name), "%s", pe.szExeFile);
    while (ancestor_count < 8 && find_process(procs, cur, &pe) && pe.th32ParentProcessID) {
        DWORD parent = pe.th32ParentProcessID;

        if (!find_process(procs, parent, &pe) || _stricmp(pe.szExeFile, self_name) != 0)
            break;
        ancestors[ancestor_count++] = cur = parent;
    }
    pe.dwSize = sizeof(pe);
    for (more = Process32First(procs, &pe); more; more = Process32Next(procs, &pe)) {
        MODULEENTRY32 me;
        HANDLE mods;
        BOOL next;

        if (pe.th32ProcessID == self || pe.th32ProcessID == 0 ||
            (skip_pid && pe.th32ProcessID == skip_pid))
            continue;
        for (i = 0; i < ancestor_count && ancestors[i] != pe.th32ProcessID; i++)
            ;
        if (i < ancestor_count)
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
