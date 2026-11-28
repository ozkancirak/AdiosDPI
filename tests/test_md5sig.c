#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"
#include "fakepackets.h"

static char sent[8][2000]; static UINT sent_len[8]; static int nsent;
BOOL test_send(HANDLE h, const VOID *p, UINT len, UINT *recv, const WINDIVERT_ADDRESS *a) {
    (void)h; (void)recv; (void)a;
    memcpy(sent[nsent], p, len); sent_len[nsent++] = len; return TRUE;
}
static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static UINT build(char *pkt, int v6, UINT dlen, int tcp_opt_bytes) {
    WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    UINT hl = v6 ? 40 : 20, thl = 20 + (UINT)tcp_opt_bytes, total = hl + thl + dlen;
    memset(pkt, 0, total);
    if (!v6) { PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)pkt; ip->Version = 4; ip->HdrLength = 5; ip->Length = htons((UINT16)total); ip->TTL = 64; ip->Protocol = IPPROTO_TCP; ip->SrcAddr = 0x0100000a; ip->DstAddr = 0x02020202; }
    else { PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)pkt; ip6->Version = 6; ip6->Length = htons((UINT16)(thl + dlen)); ip6->NextHdr = IPPROTO_TCP; ip6->HopLimit = 64; ip6->SrcAddr[0] = 1; ip6->DstAddr[0] = 2; }
    PWINDIVERT_TCPHDR t = (PWINDIVERT_TCPHDR)(pkt + hl); t->SrcPort = htons(50000); t->DstPort = htons(443); t->SeqNum = htonl(1000); t->AckNum = htonl(2000); t->HdrLength = thl / 4; t->Ack = 1; t->Psh = 1; t->Window = htons(1000);
    if (tcp_opt_bytes == 12) { char *o = pkt + hl + 20; o[0] = 1; o[1] = 1; o[2] = 8; o[3] = 10; }   /* NOP NOP timestamp */
    memset(pkt + hl + thl, 'p', dlen);
    WinDivertHelperCalcChecksums(pkt, total, &addr, 0);
    return total;
}

static void run(int v6, int opt_bytes) {
    char pkt[2000]; WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    UINT total = build(pkt, v6, 300, opt_bytes);
    PWINDIVERT_IPHDR ip = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_TCPHDR tcp = NULL; PVOID pl; UINT pn;
    nsent = 0; fake_md5sig = 1;
    CHECK(send_fake_https_request(NULL, &addr, pkt, total, v6, 0, 0, 0) == 0);
    CHECK(nsent == 1);
    {
        char again[2000]; WINDIVERT_ADDRESS a2; memset(&a2, 0, sizeof(a2));
        UINT oh = (UINT)opt_bytes;
        CHECK(WinDivertHelperParsePacket(sent[0], sent_len[0], &ip, &ip6, NULL, NULL, NULL, &tcp, NULL, &pl, &pn, NULL, NULL));
        CHECK(tcp->HdrLength * 4u == 20 + oh + 20);                    /* header grew by 20 */
        CHECK(v6 ? (ntohs(ip6->Length) == sent_len[0] - 40) : (ntohs(ip->Length) == sent_len[0]));
        CHECK(sent_len[0] == total - 300 + 20 + pn);
        CHECK(pn > 300 && ((unsigned char *)pl)[0] == 0x16 && ((unsigned char *)pl)[1] == 0x03);   /* the fake ClientHello is intact */
        {   /* the option block sits right after the old header */
            unsigned char *o = (unsigned char *)tcp + 20 + oh;
            CHECK(o[0] == 1 && o[1] == 1 && o[2] == 19 && o[3] == 18);
        }
        if (opt_bytes == 12) { unsigned char *o = (unsigned char *)tcp + 20; CHECK(o[2] == 8 && o[3] == 10); }   /* the old option is still there */
        memcpy(again, sent[0], sent_len[0]);
        WinDivertHelperCalcChecksums(again, sent_len[0], &a2, 0);
        CHECK(memcmp(again, sent[0], sent_len[0]) == 0);              /* checksums are valid */
        CHECK(ntohl(tcp->SeqNum) == 1000 && ntohl(tcp->AckNum) == 2000);   /* not a seq fake */
    }
    printf("%s, tcp options %d bytes: fake of %u bytes, tcp header %u bytes\n", v6 ? "IPv6" : "IPv4", opt_bytes, sent_len[0], (unsigned)tcp->HdrLength * 4u);
    /* off: the same call sends nothing */
    nsent = 0; fake_md5sig = 0;
    send_fake_https_request(NULL, &addr, pkt, total, v6, 0, 0, 0);
    CHECK(nsent == 0);
    /* header already at its limit: refused, nothing sent */
    {
        char big[2000]; UINT t2 = build(big, v6, 100, 40);
        nsent = 0; fake_md5sig = 1;
        send_fake_https_request(NULL, &addr, big, t2, v6, 0, 0, 0);
        CHECK(nsent == 0);
    }
}
/* --fake-ts: the fake has the timestamp 600000 back; no timestamp in the packet means no fake */
static void ts(int v6, int opt_bytes) {
    char pkt[2000]; WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    UINT total = build(pkt, v6, 300, opt_bytes), hl = v6 ? 40 : 20;
    PWINDIVERT_TCPHDR tcp = NULL; PVOID pl; UINT pn, tsval = htonl(5000000), now;
    if (opt_bytes == 12) { memcpy(pkt + hl + 20 + 4, &tsval, 4); WinDivertHelperCalcChecksums(pkt, total, &addr, 0); }
    nsent = 0; fake_ts = 1; fake_md5sig = 0;
    send_fake_https_request(NULL, &addr, pkt, total, v6, 0, 0, 0);
    if (opt_bytes != 12) { CHECK(nsent == 0); fake_ts = 0; return; }
    CHECK(nsent == 1);
    CHECK(WinDivertHelperParsePacket(sent[0], sent_len[0], NULL, NULL, NULL, NULL, NULL, &tcp, NULL, &pl, &pn, NULL, NULL));
    memcpy(&now, (char *)tcp + 20 + 4, 4);
    CHECK(ntohl(now) == 5000000 - 600000);
    CHECK(tcp->HdrLength * 4u == 32 && pn > 300 && ((unsigned char *)pl)[0] == 0x16);
    { char again[2000]; WINDIVERT_ADDRESS a2; memset(&a2, 0, sizeof(a2)); memcpy(again, sent[0], sent_len[0]);
      WinDivertHelperCalcChecksums(again, sent_len[0], &a2, 0); CHECK(memcmp(again, sent[0], sent_len[0]) == 0); }
    printf("%s: fake-ts sets the timestamp back to %lu\n", v6 ? "IPv6" : "IPv4", (unsigned long)ntohl(now));
    fake_ts = 0;
}
/* --fake-noack: the fake has data and no ACK flag; the rest of the packet stays as it was */
static void noack(int v6) {
    char pkt[2000]; WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
    UINT total = build(pkt, v6, 300, 0);
    PWINDIVERT_TCPHDR tcp = NULL; PVOID pl; UINT pn;
    nsent = 0; fake_noack = 1; fake_md5sig = 0; fake_ts = 0;
    send_fake_https_request(NULL, &addr, pkt, total, v6, 0, 0, 0);
    CHECK(nsent == 1);
    CHECK(WinDivertHelperParsePacket(sent[0], sent_len[0], NULL, NULL, NULL, NULL, NULL, &tcp, NULL, &pl, &pn, NULL, NULL));
    CHECK(tcp->Ack == 0 && tcp->Psh == 1 && ntohl(tcp->SeqNum) == 1000 && ntohl(tcp->AckNum) == 2000);
    CHECK(pn > 300 && ((unsigned char *)pl)[0] == 0x16);
    { char again[2000]; WINDIVERT_ADDRESS a2; memset(&a2, 0, sizeof(a2)); memcpy(again, sent[0], sent_len[0]);
      WinDivertHelperCalcChecksums(again, sent_len[0], &a2, 0); CHECK(memcmp(again, sent[0], sent_len[0]) == 0); }
    fake_noack = 0;
    nsent = 0; send_fake_https_request(NULL, &addr, pkt, total, v6, 0, 0, 0);
    CHECK(nsent == 0);                                                /* off: nothing is sent */
    printf("%s: fake-noack sends a fake of %u bytes without the ACK flag%s", v6 ? "IPv6" : "IPv4", sent_len[0], "\n");
}
int main(void) {
    int v;
    for (v = 0; v < 2; v++) { run(v, 0); run(v, 12); ts(v, 0); ts(v, 12); noack(v); }
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
