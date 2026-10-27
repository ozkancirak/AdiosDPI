#ifndef _DRVCHECK_H
#define _DRVCHECK_H
#include <stddef.h>

/*
 * Looks for another running program that has the WinDivert library loaded, which
 * means it is capturing packets too. The WinDivert driver service is no help:
 * it stays loaded after its last user has exited.
 *
 * Returns 1 and copies the program's file name to name, or returns 0.
 */
int other_windivert_user(char *name, size_t size);

#endif
