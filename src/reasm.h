#ifndef _REASM_H
#define _REASM_H
#include <windows.h>
#include "windivert.h"

/*
 * A ClientHello that is longer than one segment can have its server name in the second.
 * With --reasm the first segment is held back until the second one arrives (at most
 * a second), the name is looked up in both, and then both go on one after the other,
 * the first one with that knowledge.
 */

/* What is known about a ClientHello that was held back. known is 0 for every other packet. */
struct reasm_result {
    int known;
    int sni_ok;
    char *host;                 /* the name, in a buffer of this module */
    unsigned int host_len;
};

/* Keeps the packet back if nothing is held yet. Returns 1 if it did. */
int reasm_hold(const char *packet, UINT len, const WINDIVERT_ADDRESS *addr);

/* Is this packet the segment right after the held one? If so both are queued for reasm_next(). */
int reasm_join(const char *packet, UINT len, const WINDIVERT_ADDRESS *addr);

/* Takes the next queued packet, if there is one. Call it before reading a new packet. */
int reasm_next(char *packet, UINT size, UINT *len, WINDIVERT_ADDRESS *addr, struct reasm_result *result);

/* Lets a held packet go unchanged when its next segment did not come in time. */
void reasm_expire(HANDLE handle);

#endif
