/*
 * DNS poisoning check for AdiosDPI.
 *
 * Compares what the system resolver says about a domain with what a plain DNS
 * server and a DNS over HTTPS server say. Some ISPs answer blocked domains with
 * the address of their own block page; that address is the giveaway.
 */

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "lazydll.h"
#include "dnscheck.h"

#define MAX_ADDRS 16
#define TIMEOUT_MS 3000

static const unsigned char default_server[4] = {9, 9, 9, 10};   /* what the presets use (preset.c) */
#define DEFAULT_PORT 9953

/* The DoH server: Cloudflare, asked for the DNS message itself (RFC 8484), by address so no name lookup is needed. */
#define DOH_HOST L"1.1.1.1"
#define DOH_LABEL "DoH 1.1.1.1"

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

/* The DNS message that asks for the A records of domain. Returns its length, or 0. */
static int build_query(const char *domain, unsigned char *q, int size) {
    int len = 12;
    const char *p = domain;

    memset(q, 0, (size_t)size);
    q[0] = 0x5A;                /* id */
    q[1] = 0xA5;
    q[2] = 0x01;                /* recursion desired */
    q[5] = 1;                   /* one question */
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l == 0 || l > 63 || len + l + 6 > size)
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
    return len;
}

/* The A records in a reply to the query q. The reply comes from the network, so every length is checked. */
static int parse_reply(const unsigned char *r, int rlen, const unsigned char *q, uint32_t *out) {
    int n = 0, pos, i, questions, answers;

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

/* One A query over UDP. */
static int plain_lookup(const char *domain, uint32_t server, uint16_t port, uint32_t *out) {
    unsigned char q[300], r[1500];
    int len, rlen;
    DWORD timeout = TIMEOUT_MS;
    struct sockaddr_in to;
    SOCKET s;

    len = build_query(domain, q, (int)sizeof(q));
    if (!len)
        return 0;
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
    return parse_reply(r, rlen, q, out);
}

/* Base64url without padding, as RFC 8484 wants the query in the URL. Returns the length written. */
static int base64url(const unsigned char *in, int len, wchar_t *out) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i, n = 0;

    for (i = 0; i < len; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < len)
            v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len)
            v |= in[i + 2];
        out[n++] = (wchar_t)table[(v >> 18) & 63];
        out[n++] = (wchar_t)table[(v >> 12) & 63];
        if (i + 1 < len)
            out[n++] = (wchar_t)table[(v >> 6) & 63];
        if (i + 2 < len)
            out[n++] = (wchar_t)table[v & 63];
    }
    out[n] = 0;
    return n;
}

/* One A query over HTTPS (RFC 8484, GET). The certificate is checked by WinHTTP. */
static int doh_lookup(const char *domain, uint32_t *out) {
    unsigned char q[300], r[1500];
    wchar_t path[512] = L"/dns-query?dns=";
    HINTERNET session, conn, req;
    const struct winhttp_api *w = winhttp_api();
    DWORD got = 0, total = 0, status = 0, size = sizeof(status);
    int len, n = 0;

    len = build_query(domain, q, (int)sizeof(q));
    if (!len)
        return 0;
    if (!w)
        return 0;
    q[0] = q[1] = 0;            /* RFC 8484 asks for id 0 */
    base64url(q, len, path + wcslen(path));

    session = w->WinHttpOpen(L"AdiosDPI", WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return 0;
    w->WinHttpSetTimeouts(session, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, 2 * TIMEOUT_MS);
    conn = w->WinHttpConnect(session, DOH_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (conn) {
        req = w->WinHttpOpenRequest(conn, L"GET", path, NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (req) {
            if (w->WinHttpSendRequest(req, L"Accept: application/dns-message", (DWORD)-1L,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                w->WinHttpReceiveResponse(req, NULL) &&
                w->WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) &&
                status == 200) {
                while (total < sizeof(r) && w->WinHttpReadData(req, r + total, (DWORD)sizeof(r) - total, &got) && got)
                    total += got;
                n = parse_reply(r, (int)total, q, out);
            }
            w->WinHttpCloseHandle(req);
        }
        w->WinHttpCloseHandle(conn);
    }
    w->WinHttpCloseHandle(session);
    return n;
}

static double now_ms(void) {
    LARGE_INTEGER freq, count;

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}

/* The time is how long the answer took; a source that did not answer shows its time-out. */
static void print_addrs(const uint32_t *a, int n, double ms) {
    int i;
    if (!n)
        printf("(no answer)");
    for (i = 0; i < n; i++) {
        const unsigned char *b = (const unsigned char *)&a[i];
        printf("%s%u.%u.%u.%u", i ? ", " : "", b[0], b[1], b[2], b[3]);
    }
    printf("  (%.0f ms)\n", ms);
}

/* What to do about poisoned answers: redirect plain DNS, which needs the plain server to answer. */
static void print_fix(int plain_answered, const unsigned char *sb, uint16_t port) {
    if (plain_answered)
        printf("Run AdiosDPI with: --dns-addr %u.%u.%u.%u --dns-port %u\n",
               sb[0], sb[1], sb[2], sb[3], ntohs(port));
    else
        puts("The plain DNS server did not answer, so --dns-addr can't help here. Turn on\n"
             "Secure DNS (DNS over HTTPS) in Windows or in the browser instead.");
}

int dns_check(const char *domain, uint32_t server, uint16_t port) {
    WSADATA wsa;
    uint32_t sys[MAX_ADDRS], plain[MAX_ADDRS], doh[MAX_ADDRS];
    const unsigned char *sb;
    char label[24];
    double t0, t1, t2, t3;
    int ns, np, nd, i, j, k, blocked = 0, common = 0, result;

    if (!server) {
        memcpy(&server, default_server, 4);
        port = htons(DEFAULT_PORT);
    }
    sb = (const unsigned char *)&server;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        puts("Can't start Winsock.");
        return 2;
    }

    t0 = now_ms();
    ns = system_lookup(domain, sys);
    t1 = now_ms();
    np = plain_lookup(domain, server, port, plain);
    t2 = now_ms();
    nd = doh_lookup(domain, doh);          /* its time includes the HTTPS handshake */
    t3 = now_ms();
    snprintf(label, sizeof(label), "%u.%u.%u.%u:%u", sb[0], sb[1], sb[2], sb[3], ntohs(port));
    printf("DNS check for %s\n  %-21s: ", domain, "system resolver");
    print_addrs(sys, ns, t1 - t0);
    printf("  %-21s: ", label);
    print_addrs(plain, np, t2 - t1);
    printf("  %-21s: ", DOH_LABEL);
    print_addrs(doh, nd, t3 - t2);

    for (i = 0; i < ns; i++) {
        for (k = 0; k < (int)(sizeof(block_pages) / sizeof(*block_pages)); k++)
            if (memcmp(&sys[i], block_pages[k], 4) == 0)
                blocked = 1;
        for (j = 0; j < np; j++)
            if (sys[i] == plain[j])
                common = 1;
        for (j = 0; j < nd; j++)
            if (sys[i] == doh[j])
                common = 1;
    }

    if (!np && !nd) {
        puts("No answer from the DNS server or from DoH, so the answers can't be compared.\n"
             "Try another DNS server with --dns-addr and --dns-port.");
        result = 2;
    }
    else if (blocked) {
        puts("POISONED: the system resolver answers with the address of an ISP block page.");
        print_fix(np > 0, sb, port);
        result = 1;
    }
    else if (!ns) {
        puts("SUSPICIOUS: the system resolver returned nothing but the others did.");
        print_fix(np > 0, sb, port);
        result = 1;
    }
    else if (common) {
        puts("OK: the system resolver agrees with the others.");
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
