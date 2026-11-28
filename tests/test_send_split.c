#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"
#include "splitpos.h"
#include "sendsplit.h"
#define MAX_PACKET_SIZE 9016

static char pieces[16][2000];
static UINT piece_len[16];
static int npieces;
void queue_tx(HANDLE w, const char *p, UINT len, const WINDIVERT_ADDRESS *a) {
    (void)w; (void)a;
    memcpy(pieces[npieces], p, len);
    piece_len[npieces++] = len;
}

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

/* builds an IPv4 or IPv6 packet with a TCP header and dlen bytes of data, valid checksums */
static UINT build(char *pkt, int v6, UINT dlen, UINT32 seq, const char *data) {
    WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    PWINDIVERT_IPHDR ip; PWINDIVERT_IPV6HDR ip6; PWINDIVERT_TCPHDR tcp;
    UINT hl = v6 ? 40 : 20, total = hl + 20 + dlen;
    memset(pkt, 0, total);
    if (!v6) {
        ip = (PWINDIVERT_IPHDR)pkt; ip->Version = 4; ip->HdrLength = 5; ip->Length = htons((UINT16)total);
        ip->Id = htons(0x1234); ip->TTL = 64; ip->Protocol = IPPROTO_TCP; ip->SrcAddr = 0x0100000a; ip->DstAddr = 0x02020202;
    } else {
        ip6 = (PWINDIVERT_IPV6HDR)pkt; ip6->Version = 6; ip6->Length = htons((UINT16)(20 + dlen)); ip6->NextHdr = IPPROTO_TCP; ip6->HopLimit = 64;
        ip6->SrcAddr[0] = 1; ip6->DstAddr[0] = 2;
    }
    tcp = (PWINDIVERT_TCPHDR)(pkt + hl); tcp->SrcPort = htons(50000); tcp->DstPort = htons(443);
    tcp->SeqNum = htonl(seq); tcp->AckNum = htonl(777); tcp->HdrLength = 5; tcp->Psh = 1; tcp->Ack = 1; tcp->Window = htons(1000);
    memcpy(pkt + hl + 20, data, dlen);
    WinDivertHelperCalcChecksums(pkt, total, &addr, 0);
    return total;
}

static void run(int v6, const char *list, int reverse, const char *host_name, unsigned seqovl) {
    static char arena[MAX_PACKET_SIZE + 4096]; char *pkt = arena, orig[MAX_PACKET_SIZE], data[600], rebuilt[600];
    UINT dlen = 517, total, i;
    UINT32 seq0 = 4000000000u;      /* near the wrap, on purpose */
    struct split_spec spec; unsigned cuts[SPLIT_MAX]; int n, k;
    WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    PWINDIVERT_IPHDR ip = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_TCPHDR tcp = NULL; PVOID payload; UINT plen;
    unsigned covered = 0;

    for (i = 0; i < dlen; i++) data[i] = (char)(i * 7 + 3);
    memcpy(data + 120, host_name, strlen(host_name));
    total = build(pkt, v6, dlen, seq0, data);
    memcpy(orig, pkt, total);
    memset(pkt + total, 0xCD, 2000);                 /* what would be the next packet of a batch */
    WinDivertHelperParsePacket(pkt, total, &ip, &ip6, NULL, NULL, NULL, &tcp, NULL, &payload, &plen, NULL, NULL);
    CHECK(split_parse(list, &spec));
    n = split_resolve(&spec, (const char *)payload, plen, data[0] ? (const char *)payload + 120 : NULL, (UINT)strlen(host_name), cuts);
    npieces = 0;
    send_split(NULL, addr, pkt, total, payload, plen, !v6, v6, ip, ip6, tcp, cuts, n, seqovl, reverse);
    CHECK(npieces == n + 1);
    { unsigned z; for (z = 0; z < 2000; z++) if ((unsigned char)pkt[total + z] != 0xCD) { printf("FAIL: wrote past the packet at +%u\n", z); fails++; break; } }
    CHECK(memcmp(pkt, orig, total) == 0);           /* the packet is whole again afterwards */
    memset(rebuilt, 0, sizeof(rebuilt));
    for (k = 0; k < npieces; k++) {
        char copy[2000]; PWINDIVERT_IPHDR pi = NULL; PWINDIVERT_IPV6HDR pi6 = NULL; PWINDIVERT_TCPHDR pt = NULL; PVOID pp; UINT pl;
        UINT want_piece = reverse ? (UINT)(npieces - 1 - k) : (UINT)k;
        unsigned from = want_piece == 0 ? 0 : cuts[want_piece - 1];
        unsigned to = want_piece == (UINT)n ? dlen : cuts[want_piece];
        unsigned pad = want_piece == 0 ? seqovl : 0;        /* only the piece that starts the data starts early */
        unsigned z;
        memcpy(copy, pieces[k], piece_len[k]);
        CHECK(WinDivertHelperParsePacket(copy, piece_len[k], &pi, &pi6, NULL, NULL, NULL, &pt, NULL, &pp, &pl, NULL, NULL));
        CHECK(pl == to - from + pad);
        CHECK(ntohl(pt->SeqNum) == seq0 + from - pad);
        CHECK(v6 ? (ntohs(pi6->Length) == 20 + pl) : (ntohs(pi->Length) == 40 + pl));
        for (z = 0; z < pad; z++) CHECK(((unsigned char *)pp)[z] == 0);
        CHECK(memcmp((char *)pp + pad, data + from, pl - pad) == 0);
        /* checksums valid: recompute on a copy and compare */
        {
            char again[2000]; WINDIVERT_ADDRESS a2; memset(&a2, 0, sizeof(a2));
            memcpy(again, pieces[k], piece_len[k]);
            WinDivertHelperCalcChecksums(again, piece_len[k], &a2, 0);
            CHECK(memcmp(again, pieces[k], piece_len[k]) == 0);
        }
        CHECK(pt->DstPort == htons(443) && pt->Psh == 1 && ntohl(pt->AckNum) == 777);
        memcpy(rebuilt + from, (char *)pp + pad, pl - pad);
        covered += pl - pad;
    }
    CHECK(covered == dlen && memcmp(rebuilt, data, dlen) == 0);
    printf("%s  split-pos \"%s\"%s seqovl %u -> cuts:", v6 ? "IPv6" : "IPv4", list, reverse ? " (reverse)" : "", seqovl);
    for (k = 0; k < n; k++) printf(" %u", cuts[k]);
    printf("   pieces in sent order:");
    for (k = 0; k < npieces; k++) { PWINDIVERT_TCPHDR pt = NULL; WinDivertHelperParsePacket(pieces[k], piece_len[k], NULL, NULL, NULL, NULL, NULL, &pt, NULL, NULL, NULL, NULL, NULL); printf(" +%u", (unsigned)(ntohl(pt->SeqNum) - seq0)); }
    printf("\n");
}

/* one TLS record cut in two: lengths, bytes and checksums of the new packet */
static void tlsrec(int v6, unsigned cut) {
    static char pkt[2000], out[2000], again[2000];
    char data[517]; UINT i, total, n, hl = v6 ? 40 : 20, d = hl + 20;
    WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    for (i = 0; i < sizeof(data); i++) data[i] = (char)(i * 5 + 1);
    data[0] = 0x16; data[1] = 3; data[2] = 1; data[3] = 0x02; data[4] = 0x00;       /* one record of 512 bytes */
    total = build(pkt, v6, sizeof(data), 1000, data);
    n = tls_record_split(out, pkt, total, d, sizeof(data), !v6, cut);
    CHECK(n == total + 5);
    CHECK(tls_record_split(out, pkt, total, d, sizeof(data), !v6, 5) == 0);          /* inside the header: no */
    CHECK(tls_record_split(out, pkt, total, d, sizeof(data), !v6, sizeof(data)) == 0);
    CHECK(((unsigned char)out[d + 3] << 8 | (unsigned char)out[d + 4]) == cut - 5);   /* first record */
    CHECK(((unsigned char)out[d + cut + 3] << 8 | (unsigned char)out[d + cut + 4]) == 512 - (cut - 5));
    CHECK(memcmp(out + d + 5, data + 5, cut - 5) == 0 && memcmp(out + d + cut + 5, data + cut, sizeof(data) - cut) == 0);
    CHECK(memcmp(out + d + cut, data, 3) == 0);                                       /* same type and version */
    WinDivertHelperCalcChecksums(out, n, &addr, 0);
    CHECK(ntohs(v6 ? ((PWINDIVERT_IPV6HDR)out)->Length : ((PWINDIVERT_IPHDR)out)->Length) == n - (v6 ? 40 : 0));
    memcpy(again, out, n); WinDivertHelperCalcChecksums(again, n, &addr, 0);
    CHECK(memcmp(again, out, n) == 0);
    printf("%s  tlsrec at %u ok\n", v6 ? "IPv6" : "IPv4", cut);
}

int main(void) {
    int v;
    for (v = 0; v < 2; v++) {
        tlsrec(v, 6);
        tlsrec(v, 130);
    }
    for (v = 0; v < 2; v++) {
        run(v, "1,midsld", 0, "cdn.discordapp.com", 0);
        run(v, "1,midsld", 1, "cdn.discordapp.com", 0);
        run(v, "sniext+1,host,midsld,endhost-2,-10", 0, "discord.com", 0);
        run(v, "sniext+1,host,midsld,endhost-2,-10", 1, "discord.com", 0);
        run(v, "2", 1, "x.example.org", 0);
        run(v, "1,midsld", 0, "cdn.discordapp.com", 20);
        run(v, "1,midsld", 1, "cdn.discordapp.com", 568);
        run(v, "sniext+1,host,midsld", 1, "discord.com", 1000);
        run(v, "2", 0, "x.example.org", 1);
    }
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
