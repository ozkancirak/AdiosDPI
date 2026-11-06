#ifndef _DNSCHECK_H
#define _DNSCHECK_H
#include <stdint.h>

/*
 * Asks the system resolver, a plain DNS server and a DNS over HTTPS server
 * (1.1.1.1) for the IPv4 addresses of domain, prints the answers and says whether
 * the system one looks poisoned.
 * server and port are in network byte order; 0 means 9.9.9.10 port 9953.
 *
 * Returns 0 when no poisoning was found (the answers agree, or differ the way a
 * CDN makes them differ), 1 when the system resolver gives a block page address
 * or nothing at all, 2 when neither the DNS server nor DoH gave an answer.
 */
int dns_check(const char *domain, uint32_t server, uint16_t port);

/*
 * The same comparison without any output, for --probe. The server is the one the
 * presets use. addr gets the address to connect to: the real one when the system
 * resolver is poisoned, otherwise what the system resolver gave (0 if nothing).
 */
enum { DNS_OK, DNS_POISONED, DNS_UNKNOWN, DNS_UNSURE };
int dns_verdict(const char *domain, uint32_t *addr);

#endif
