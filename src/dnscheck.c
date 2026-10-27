/*
 * DNS poisoning check for AdiosDPI.
 *
 * Compares what the system resolver says about a domain with what a plain DNS
 * server says. Some ISPs answer blocked domains with the address of their own
 * block page; that address is the giveaway.
 */

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "dnscheck.h"

#define MAX_ADDRS 16
#define TIMEOUT_MS 3000

static const unsigned char default_server[4] = {77, 88, 8, 8};
#define DEFAULT_PORT 1253

/* Addresses ISPs are known to answer with for blocked sites. */
static const unsigned char block_pages[][4] = {
    {195, 175, 254, 2},
};

static int system_lookup(const char *domain, uint32_t *out) {
    struct addrinfo hints, *res, *p;
    int n = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(domain, NULL, &hints, &res) != 0)
        return 0;
    for (p = res; p && n < MAX_ADDRS; p = p->ai_next) {
        struct sockaddr_in sa;
        if (p->ai_addrlen < sizeof(sa))
            continue;
        memcpy(&sa, p->ai_addr, sizeof(sa));
        out[n++] = sa.sin_addr.s_addr;
    }
    freeaddrinfo(res);
    return n;
}

/* Position after the (possibly compressed) name at pos, or -1. */
static int skip_name(const unsigned char *m, int len, int pos) {
    while (pos < len) {
        int l = m[pos];
        if (l == 0)
            return pos + 1;
        if ((l & 0xC0) == 0xC0)
            return pos + 2 <= len ? pos + 2 : -1;
        if (l & 0xC0)
            return -1;
        pos += l + 1;
    }
    return -1;
}

/* One A query over UDP. The reply comes from the network, so every length is checked. */
static int plain_lookup(const char *domain, uint32_t server, uint16_t port, uint32_t *out) {
    unsigned char q[300], r[1500];
    int len = 12, n = 0, rlen, pos, i, questions, answers;
    const char *p = domain;
    DWORD timeout = TIMEOUT_MS;
    struct sockaddr_in to;
    SOCKET s;

    memset(q, 0, sizeof(q));
    q[0] = 0x5A;                /* id */
    q[1] = 0xA5;
    q[2] = 0x01;                /* recursion desired */
    q[5] = 1;                   /* one question */
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l == 0 || l > 63 || len + l + 6 > (int)sizeof(q))
            return 0;
        q[len++] = (unsigned char)l;
        memcpy(q + len, p, (size_t)l);
        len += l;
        if (!dot)
            break;
        p = dot + 1;
    }
    q[len++] = 0;               /* end of name */
    q[len++] = 0;               /* type A */
    q[len++] = 1;
    q[len++] = 0;               /* class IN */
    q[len++] = 1;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = server;
    to.sin_port = port;
    if (sendto(s, (const char *)q, len, 0, (struct sockaddr *)&to, sizeof(to)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    rlen = recv(s, (char *)r, (int)sizeof(r), 0);
    closesocket(s);
    if (rlen < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0F) != 0)
        return 0;

    questions = (r[4] << 8) | r[5];
    answers = (r[6] << 8) | r[7];
    pos = 12;
    for (i = 0; i < questions; i++) {
        pos = skip_name(r, rlen, pos);
        if (pos < 0 || pos + 4 > rlen)
            return 0;
        pos += 4;
    }
    for (i = 0; i < answers && n < MAX_ADDRS; i++) {
        int type, rdlen;
        pos = skip_name(r, rlen, pos);
        if (pos < 0 || pos + 10 > rlen)
            break;
        type = (r[pos] << 8) | r[pos + 1];
        rdlen = (r[pos + 8] << 8) | r[pos + 9];
        pos += 10;
        if (pos + rdlen > rlen)
            break;
        if (type == 1 && rdlen == 4)
            memcpy(&out[n++], r + pos, 4);
        pos += rdlen;
    }
    return n;
}

static void print_addrs(const uint32_t *a, int n) {
    int i;
    if (!n)
        printf("(no answer)");
    for (i = 0; i < n; i++) {
        const unsigned char *b = (const unsigned char *)&a[i];
        printf("%s%u.%u.%u.%u", i ? ", " : "", b[0], b[1], b[2], b[3]);
    }
    printf("\n");
}

int dns_check(const char *domain, uint32_t server, uint16_t port) {
    WSADATA wsa;
    uint32_t sys[MAX_ADDRS], trusted[MAX_ADDRS];
    const unsigned char *sb;
    char label[24];
    int ns, nt, i, j, k, blocked = 0, common = 0, result;

    if (!server) {
        memcpy(&server, default_server, 4);
        port = htons(DEFAULT_PORT);
    }
    sb = (const unsigned char *)&server;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        puts("Can't start Winsock.");
        return 2;
    }

    ns = system_lookup(domain, sys);
    nt = plain_lookup(domain, server, port, trusted);
    snprintf(label, sizeof(label), "%u.%u.%u.%u:%u", sb[0], sb[1], sb[2], sb[3], ntohs(port));
    printf("DNS check for %s\n  %-21s: ", domain, "system resolver");
    print_addrs(sys, ns);
    printf("  %-21s: ", label);
    print_addrs(trusted, nt);

    for (i = 0; i < ns; i++) {
        for (k = 0; k < (int)(sizeof(block_pages) / sizeof(*block_pages)); k++)
            if (memcmp(&sys[i], block_pages[k], 4) == 0)
                blocked = 1;
        for (j = 0; j < nt; j++)
            if (sys[i] == trusted[j])
                common = 1;
    }

    if (!nt) {
        puts("No answer from the DNS server, so the answers can't be compared.\n"
             "Try another one with --dns-addr and --dns-port.");
        result = 2;
    }
    else if (blocked) {
        printf("POISONED: the system resolver answers with the address of an ISP block page.\n"
               "Run AdiosDPI with: --dns-addr %u.%u.%u.%u --dns-port %u\n",
               sb[0], sb[1], sb[2], sb[3], ntohs(port));
        result = 1;
    }
    else if (!ns) {
        printf("SUSPICIOUS: the system resolver returned nothing but the DNS server did.\n"
               "Run AdiosDPI with: --dns-addr %u.%u.%u.%u --dns-port %u\n",
               sb[0], sb[1], sb[2], sb[3], ntohs(port));
        result = 1;
    }
    else if (common) {
        puts("OK: both resolvers agree.");
        result = 0;
    }
    else {
        puts("No block page found. The answers differ, which a CDN can cause (each resolver\n"
             "gets other addresses); if the site still does not open, DNS may be the cause.");
        result = 0;
    }
    WSACleanup();
    return result;
}
