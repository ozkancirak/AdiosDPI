#ifndef _DRVCHECK_H
#define _DRVCHECK_H
#include <stddef.h>
#include <windows.h>

/*
 * Lists the other running programs that have the WinDivert library loaded, which
 * means they capture packets too. The WinDivert driver service is no help: it
 * stays loaded after its last user has exited.
 *
 * Writes their file names, separated by ", ", to names and returns how many
 * there are. This program and the process skip_pid (0 for none) are left out.
 */
int windivert_users(char *names, size_t size, DWORD skip_pid);

#endif
