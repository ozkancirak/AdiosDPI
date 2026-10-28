#ifndef _PROBE_H
#define _PROBE_H

/*
 * Tries to open https://domain/ without any tool and then with each preset in
 * turn, least intrusive first, and says which one works. Every candidate runs
 * as a child process that is stopped again before the next one starts.
 *
 * Returns 0 when something works, 1 when nothing does.
 */
int probe(const char *domain);

#endif
