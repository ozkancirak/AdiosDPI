/*
 * AdiosDPI — Passive DPI blocker and Active DPI circumvention utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include "windivert.h"
#include "adiosdpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "tls.h"
#include "reasm.h"
#include "quic.h"
#include "dnsredir.h"
#include "dnscheck.h"
#include "preset.h"
#include "drvcheck.h"
#include "probe.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "fakepackets.h"

// My mingw installation does not load inet_pton definition for some reason
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);

#define ADIOSDPI_VERSION "v0.1.0-dev"

#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4

#define DIVERT_NO_LOCALNETSv4_DST "(" \
                   "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                   "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                   "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                   "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                   "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)" \
                   ")"
#define DIVERT_NO_LOCALNETSv4_SRC "(" \
                   "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                   "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                   "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                   "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                   "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255)" \
                   ")"

#define DIVERT_NO_LOCALNETSv6_DST "(" \
                   "(ipv6.DstAddr > ::1) and " \
                   "(ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and " \
                   "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and " \
                   "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and " \
                   "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0)" \
                   ")"
#define DIVERT_NO_LOCALNETSv6_SRC "(" \
                   "(ipv6.SrcAddr > ::1) and " \
                   "(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and " \
                   "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and " \
                   "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and " \
                   "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0)" \
                   ")"

/* #IPID# is a template to find&replace */
#define IPID_TEMPLATE "#IPID#"
#define MAXPAYLOADSIZE_TEMPLATE "#MAXPAYLOADSIZE#"
#define PASSIVE_TEMPLATE "#PASSIVE#"
#define TCPOFF_TEMPLATE "#TCPOFF#"
#define SYNACK_TEMPLATE "#SYNACK#"
#define HTTPALL_TEMPLATE "#HTTPALL#"
#define HTTPREQ_TEMPLATE "#HTTPREQ#"
/* GET, HEAD, POST, PUT, DELETE, CONNECT and OPTIONS: the first four bytes of every HTTP request. */
#define HTTP_METHODS_FILTER "tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x48454144 or tcp.Payload32[0] == 0x504F5354 or tcp.Payload32[0] == 0x50555420 or tcp.Payload32[0] == 0x44454C45 or tcp.Payload32[0] == 0x434F4E4E or tcp.Payload32[0] == 0x4F505449"
#define FILTER_STRING_TEMPLATE \
        "(" TCPOFF_TEMPLATE "tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
        "((inbound and (" \
         "(" \
          "(" \
           "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) " IPID_TEMPLATE \
           ") and " \
           PASSIVE_TEMPLATE "tcp.SrcPort == 80 and tcp.Ack" \
          ") or " \
          "(" SYNACK_TEMPLATE "(tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn)" \
         ")" \
         " and (" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC "))) or " \
        "(outbound and " \
         /* On 443 only the first segment of a TLS handshake record is rewritten, unless -w looks for HTTP there. */ \
         "((tcp.DstPort == 443 and (" HTTPALL_TEMPLATE "tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03)) or " \
          "(tcp.DstPort == 80 and (" HTTPREQ_TEMPLATE HTTP_METHODS_FILTER "))) and tcp.Ack and tcp.PayloadLength > 0 and " \
         "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST "))" \
        "))"
#define FILTER_QUIC_INITIAL "outbound and !impostor and !loopback and udp " \
        "and udp.DstPort == 443 and udp.PayloadLength >= 1200 " \
        "and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01"
#define FILTER_PASSIVE_STRING_TEMPLATE "inbound and ip and tcp and " \
        "!impostor and !loopback and " \
        "(true " IPID_TEMPLATE ") and " \
        "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and " \
        DIVERT_NO_LOCALNETSv4_SRC

#define SET_HTTP_FRAGMENT_SIZE_OPTION(fragment_size) do { \
    if (!http_fragment_size) { \
        http_fragment_size = (unsigned int)fragment_size; \
    } \
    else if (http_fragment_size != (unsigned int)fragment_size) { \
        printf( \
            "WARNING: HTTP fragment size is already set to %u, not changing.\n", \
            http_fragment_size \
        ); \
    } \
} while (0)

#define TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() \
    if ((packet_v4 && tcp_handle_outgoing(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr, \
                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                        &tcp_conn_info, 0)) \
        || \
        (packet_v6 && tcp_handle_outgoing(ppIpV6Hdr->SrcAddr, ppIpV6Hdr->DstAddr, \
                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                        &tcp_conn_info, 1)))

#define TCP_HANDLE_OUTGOING_FAKE_PACKET(func) do { \
    should_send_fake = 1; \
    if (do_auto_ttl || ttl_min_nhops) { \
        TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() { \
            if (do_auto_ttl) { \
                /* If Auto TTL mode */ \
                ttl_of_fake_packet = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2, \
                                                      ttl_min_nhops, auto_ttl_max); \
                if (do_tcp_verb) { \
                    printf("Connection TTL = %d, Fake TTL = %d\n", tcp_conn_info.ttl, ttl_of_fake_packet); \
                } \
            } \
            else if (ttl_min_nhops) { \
                /* If not Auto TTL mode but --min-ttl is set */ \
                if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0)) { \
                    /* Send only if nhops >= min_ttl */ \
                    should_send_fake = 0; \
                } \
            } \
        } \
    } \
    if (should_send_fake) \
        func(w_filter, &addr, packet, packetLen, packet_v6, \
             ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq); \
} while (0)

enum ERROR_CODE{
    ERROR_DEFAULT = 1,
    ERROR_PORT_BOUNDS,
    ERROR_DNS_V4_ADDR,
    ERROR_DNS_V6_ADDR,
    ERROR_DNS_V4_PORT,
    ERROR_DNS_V6_PORT,
    ERROR_BLACKLIST_LOAD,
    ERROR_AUTOTTL,
    ERROR_ATOUSI,
    ERROR_AUTOB
};

static int running_from_service = 0;
static volatile int exiting = 0;
static HANDLE filters[MAX_FILTERS];
static int filter_num = 0;
static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static struct option long_options[] = {
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-backup",  required_argument, 0,  'B' },
    {"dnsv6-backup",required_argument, 0,  'C' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"dns-check",   required_argument, 0,  'D' },
    {"log",         required_argument, 0,  'L' },
    {"blacklist",   required_argument, 0,  'b' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"frag-in-sni", no_argument,       0,  'M' },
    {"reasm",       no_argument,       0,  'R' },
    {"fake-quic",   required_argument, 0,  'Q' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex", required_argument, 0,  'u' },
    {"fake-with-sni", required_argument, 0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  't' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {0,             0,                 0,   0  }
};

static char *filter_string = NULL;
static char *filter_passive_string = NULL;

static void add_filter_str(int proto, int port) {
    const char *udp = " or (udp and !impostor and !loopback and " \
                      "(udp.SrcPort == %d or udp.DstPort == %d))";
    const char *tcp = " or (tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
                      "(tcp.SrcPort == %d or tcp.DstPort == %d))";

    char *current_filter = filter_string;
    size_t new_filter_size = strlen(current_filter) +
            (proto == IPPROTO_UDP ? strlen(udp) : strlen(tcp)) + 16;
    char *new_filter = malloc(new_filter_size);

    strcpy(new_filter, current_filter);
    if (proto == IPPROTO_UDP)
        sprintf(new_filter + strlen(new_filter), udp, port, port);
    else
        sprintf(new_filter + strlen(new_filter), tcp, port, port);

    filter_string = new_filter;
    free(current_filter);
}

/*
 * Hands the answers of one DNS server to the program: those from this address and port, and nothing else.
 * A backup may use a port other things use as well (5353 is also multicast DNS), so the port alone won't do.
 */
static void add_dns_reply_filter(int ipv6, const char *addr, int port) {
    const char *fmt = " or (inbound and udp and !impostor and !loopback and %s.SrcAddr == %s and udp.SrcPort == %d)";
    char *current_filter = filter_string;
    size_t size = strlen(current_filter) + strlen(fmt) + strlen(addr) + 24;
    char *new_filter = malloc(size);

    if (!new_filter) {
        puts("Out of memory.");
        exit(ERROR_DEFAULT);
    }
    strcpy(new_filter, current_filter);
    sprintf(new_filter + strlen(new_filter), fmt, ipv6 ? "ipv6" : "ip", addr, port);
    filter_string = new_filter;
    free(current_filter);
}

/*
 * "1.2.3.4", "1.2.3.4:5353", "2001:db8::1" or "[2001:db8::1]:5353" to an address and a port (53 when
 * there is none). The address is also given back as text for the filter.
 */
static int parse_dns_server(const char *text, int ipv6, dns_server_t *out, char *addr, size_t addr_size) {
    const char *end = NULL, *colon;
    unsigned long port = 53;
    char *stop;
    size_t len;

    memset(out, 0, sizeof(*out));
    if (ipv6 && text[0] == '[') {
        end = strchr(text, ']');
        if (!end || (end[1] != '\0' && end[1] != ':'))
            return 0;
        len = (size_t)(end - text - 1);
        text++;
        if (end[1] == ':') {
            port = strtoul(end + 2, &stop, 10);
            if (*stop)
                return 0;
        }
    }
    else if (!ipv6 && (colon = strchr(text, ':')) != NULL) {
        len = (size_t)(colon - text);
        port = strtoul(colon + 1, &stop, 10);
        if (*stop)
            return 0;
    }
    else {
        len = strlen(text);
    }
    if (len == 0 || len >= addr_size || port == 0 || port > 65535)
        return 0;
    memcpy(addr, text, len);
    addr[len] = '\0';
    if (inet_pton(ipv6 ? AF_INET6 : AF_INET, addr, out->ip) != 1)
        return 0;
    out->port = htons((uint16_t)port);
    return 1;
}

/* Hands outgoing QUIC Initial packets to the program as well. */
static void add_quic_filter(void) {
    const char *quic = " or (" FILTER_QUIC_INITIAL ")";
    char *new_filter = malloc(strlen(filter_string) + strlen(quic) + 1);

    if (!new_filter)
        die();
    strcpy(new_filter, filter_string);
    strcat(new_filter, quic);
    free(filter_string);
    filter_string = new_filter;
}

static void add_ip_id_str(int id) {
    char *newstr;
    const char *ipid = " or ip.Id == %d";
    char *addfilter = malloc(strlen(ipid) + 16);

    sprintf(addfilter, ipid, id);

    newstr = repl_str(filter_string, IPID_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;

    newstr = repl_str(filter_passive_string, IPID_TEMPLATE, addfilter);
    free(filter_passive_string);
    filter_passive_string = newstr;
}

static void add_maxpayloadsize_str(unsigned short maxpayload) {
    char *newstr;
    /* 0x47455420 is "GET ", 0x504F5354 is "POST", big endian. */
    const char *maxpayloadsize_str =
        "and (tcp.PayloadLength ? tcp.PayloadLength < %hu " \
          "or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 " \
          "or (tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03): true)";
    char *addfilter = malloc(strlen(maxpayloadsize_str) + 16);

    sprintf(addfilter, maxpayloadsize_str, maxpayload);

    newstr = repl_str(filter_string, MAXPAYLOADSIZE_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;
}

/* Which parts of the filter the chosen options need. */
struct filter_features {
    int passive;        /* -p: inbound port 80 data, to drop redirects */
    int tcp;            /* any TCP trick at all */
    int synack;         /* inbound SYN+ACK: window size and distance */
    int http_all;       /* -w: HTTP on port 443 too */
    int http_requests;  /* port 80: only packets that start like an HTTP request */
};

static void replace_token(char **str, const char *token, const char *with) {
    char *newstr = repl_str(*str, token, with);

    free(*str);
    *str = newstr;
}

static void finalize_filter_strings(const struct filter_features *f) {
    replace_token(&filter_string, IPID_TEMPLATE, "");
    replace_token(&filter_string, MAXPAYLOADSIZE_TEMPLATE, "");
    replace_token(&filter_string, PASSIVE_TEMPLATE, f->passive ? "" : "false and ");
    replace_token(&filter_string, TCPOFF_TEMPLATE, f->tcp ? "" : "false and ");
    replace_token(&filter_string, SYNACK_TEMPLATE, f->synack ? "" : "false and ");
    replace_token(&filter_string, HTTPALL_TEMPLATE, f->http_all ? "true or " : "");
    replace_token(&filter_string, HTTPREQ_TEMPLATE, f->http_requests ? "" : "true or ");
    replace_token(&filter_passive_string, IPID_TEMPLATE, "");
}

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    // naive implementation
    if (nlen > hlen) return NULL;
    size_t i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return (char*)(haystack+i);
        }
    }
    return NULL;
}

unsigned short int atousi(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    enum {
        limitValue=0xFFFFu
    };

    if(res > limitValue) {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    return (unsigned short int)res;
}

BYTE atoub(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    enum {
        limitValue=0xFFu
    };

    if(res > limitValue) {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    return (BYTE)res;
}


static HANDLE init(char *filter, UINT64 flags) {
    LPTSTR errormessage = NULL;
    DWORD errorcode = 0;
    filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (filter != INVALID_HANDLE_VALUE)
        return filter;
    errorcode = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)&errormessage, 0, NULL);
    printf("Error opening filter: %lu %s\n", errorcode, errormessage);
    LocalFree(errormessage);
    if (errorcode == 2)
        printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
    else if (errorcode == 654)
        printf("An incompatible version of the WinDivert driver is currently loaded.\n"
               "Please unload it with the following commands ran as administrator:\n\n"
               "sc stop windivert\n"
               "sc delete windivert\n"
               "sc stop windivert14\n"
               "sc delete windivert14\n");
    else if (errorcode == 1275)
        printf("This error occurs for various reasons, including:\n"
               "the WinDivert driver is blocked by security software; or\n"
               "you are using a virtualization environment that does not support drivers.\n");
    else if (errorcode == 1753)
        printf("This error occurs when the Base Filtering Engine service has been disabled.\n"
               "Enable Base Filtering Engine service.\n");
    else if (errorcode == 577)
        printf("Could not load driver due to invalid digital signature.\n"
               "Windows Server 2016 systems must have secure boot disabled to be \n"
               "able to load WinDivert driver.\n"
               "Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
               "https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
               "WARNING! If you see this error on Windows 7, it means your system is horribly "
               "outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
               "Most probably, you don't have security patches installed and anyone in you LAN or "
               "public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
               "You should install updates IMMEDIATELY.\n");
    return NULL;
}

static int deinit(HANDLE handle) {
    if (handle) {
        WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle);
        return TRUE;
    }
    return FALSE;
}

void deinit_all() {
    for (int i = 0; i < filter_num; i++) {
        deinit(filters[i]);
    }
}

/*
 * Asks the main loop to finish. It only wakes the loop up (a shut down handle fails
 * WinDivertRecv with ERROR_NO_DATA); the handles are closed by main() afterwards,
 * so nothing is closed while the loop is still using it. Safe to call from another thread.
 */
void shutdown_all(void) {
    int i;

    exiting = 1;
    for (i = 0; i < filter_num; i++) {
        if (filters[i])
            WinDivertShutdown(filters[i], WINDIVERT_SHUTDOWN_BOTH);
    }
}

static void sigint_handler(int sig __attribute__((unused))) {
    shutdown_all();
}

static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;

    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = (char) toupper(pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    /* First check if this is HTTP 302 redirect */
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0)
    {
        /* Then check if this is a redirect to new http site with Connection: close */
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    /* Search for the header */
    hdr_begin = dumb_memmem(pktdata, pktlen,
                hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    /* Set header address */
    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    /* Search for header end (\r\n) */
    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (uintptr_t)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (uintptr_t)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static inline void change_window_size(const PWINDIVERT_TCPHDR ppTcpHdr, unsigned int size) {
    if (size >= 1 && size <= 0xFFFFu) {
        ppTcpHdr->Window = htons((u_short)size);
    }
}

/* HTTP method end without trailing space */
static PVOID find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        /* Try to find HTTP method in a second part of fragmented packet */
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0
           )
        {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}

/** Fragment and send the packet.
 *
 * This function cuts off the end of the packet (step=0) or
 * the beginning of the packet (step=1) with fragment_size bytes.
 */
static void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                        char *packet, UINT packetLen, PVOID packet_data,
                        UINT packet_dataLen, int packet_v4, int packet_v6,
                        PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                        PWINDIVERT_TCPHDR ppTcpHdr,
                        unsigned int fragment_size, int step) {
    char packet_bak[MAX_PACKET_SIZE];
    memcpy(packet_bak, packet, packetLen);
    UINT orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    if (step == 0) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) -
                packet_dataLen + fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) -
                packet_dataLen + fragment_size
            );
        //printf("step0 (%d:%d), pp:%d, was:%d, now:%d\n",
        //                packet_v4, packet_v6, ntohs(ppIpHdr->Length),
        //                packetLen, packetLen - packet_dataLen + fragment_size);
        packetLen = packetLen - packet_dataLen + fragment_size;
    }

    else if (step == 1) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) - fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) - fragment_size
            );
        //printf("step1 (%d:%d), pp:%d, was:%d, now:%d\n", packet_v4, packet_v6, ntohs(ppIpHdr->Length),
        //                packetLen, packetLen - fragment_size);
        memmove(packet_data,
                (char*)packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;

        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
    }

    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;

    WinDivertHelperCalcChecksums(
        packet, packetLen, &addr, 0
    );
    WinDivertSend(
        w_filter, packet,
        packetLen,
        NULL, &addr
    );
    memcpy(packet, packet_bak, orig_packetLen);
    //printf("Sent native fragment of %d size (step%d)\n", packetLen, step);
}

/*
 * What is left to do once the filter is open. Looking through every running program takes about half
 * a second, so it runs beside the start-up instead of in front of it: the filter opens at once and the
 * warning, if any, follows.
 *
 * Then the working set is emptied. Start-up touched the pages of every library it loaded, about 5 MB,
 * nearly all of it shared with other programs; the loop needs a small part of that, and those pages
 * come back as it uses them (the first connection afterwards takes a few milliseconds longer).
 */
static DWORD WINAPI finish_startup(LPVOID unused) {
    char others[512];

    (void)unused;
    if (windivert_users(others, sizeof(others), 0))
        printf("\nWARNING: WinDivert is loaded by %s. Two bypass tools at once can break connections;\n"
               "close the other one first if sites stop opening.\n", others);
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    return 0;
}

static int print_status(void) {
    DWORD pid = 0;
    char users[512];

    printf("AdiosDPI " ADIOSDPI_VERSION "\n");
    service_status(&pid);
    if (windivert_users(users, sizeof(users), pid))
        printf("WinDivert: also loaded by %s\n", users);
    else
        puts("WinDivert: not loaded by any other program");
    puts("DNS      : run --dns-check <domain> to see whether DNS is poisoned");
    return 0;
}

/* Sends everything the program prints to a file. A service has no console, so this is how to see its output. */
static int open_log(const char *name) {
    time_t now = time(NULL);
    char stamp[32] = "";

    if (!freopen(name, "w", stdout)) {
        fprintf(stderr, "Can't open the log file %s.\n", name);
        return 0;
    }
    dup2(fileno(stdout), fileno(stderr));
    setvbuf(stdout, NULL, _IONBF, 0);       /* the file is up to date if the program is stopped */
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("Log started %s\n", stamp);
    return 1;
}

#define BATCH_SIZE 64
/* Room for 64 normal packets, and still enough for any single packet the driver can hand over. */
#define BATCH_BUF_SIZE (BATCH_SIZE * 2048)

static char batch[BATCH_BUF_SIZE];
static WINDIVERT_ADDRESS batch_addrs[BATCH_SIZE];
static char tx_batch[BATCH_BUF_SIZE];
static WINDIVERT_ADDRESS tx_addrs[BATCH_SIZE];
static UINT tx_len;
static int tx_count;

/* Hand the queued packets to the driver in one call. */
static void flush_tx(HANDLE w_filter) {
    if (tx_count == 0)
        return;
    if (tx_count == 1)
        WinDivertSend(w_filter, tx_batch, tx_len, NULL, &tx_addrs[0]);
    else
        WinDivertSendEx(w_filter, tx_batch, tx_len, NULL, 0, tx_addrs,
                        (UINT)tx_count * sizeof(WINDIVERT_ADDRESS), NULL);
    tx_len = 0;
    tx_count = 0;
}

static void queue_tx(HANDLE w_filter, const char *packet, UINT len,
                     const WINDIVERT_ADDRESS *addr) {
    if (tx_count >= BATCH_SIZE || tx_len + len > sizeof(tx_batch))
        flush_tx(w_filter);
    memcpy(tx_batch + tx_len, packet, len);
    tx_addrs[tx_count] = *addr;
    tx_len += len;
    tx_count++;
}

/* Length of the first packet in a batch: the packets are packed without gaps. */
static UINT batch_packet_len(const char *packet, UINT len) {
    uint16_t total;

    if (len >= 20 && ((unsigned char)packet[0] >> 4) == 4) {
        memcpy(&total, packet + 2, sizeof(total));
        total = ntohs(total);
        if (total >= 20 && total <= len)
            return total;
    }
    else if (len >= 40 && ((unsigned char)packet[0] >> 4) == 6) {
        memcpy(&total, packet + 4, sizeof(total));
        total = ntohs(total);
        if ((UINT)total + 40 <= len)
            return (UINT)total + 40;
    }
    return len;
}

int main(int argc, char *argv[]) {
    static enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    bool debug_exit = false;
    int i, should_reinject, should_recalc_checksum = 0;
    int sni_ok = 0;
    int opt;
    int packet_v4, packet_v6;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    char packet_buf[MAX_PACKET_SIZE];
    char *packet = packet_buf;
    PVOID packet_data;
    UINT packetLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    PWINDIVERT_UDPHDR ppUdpHdr;
    conntrack_info_t dns_conn_info;
    dns_server_t dns_target, dnsv4_backup, dnsv6_backup;
    int have_dnsv4_backup = 0, have_dnsv6_backup = 0;
    char dns_backup_text[64];
    tcp_conntrack_info_t tcp_conn_info;

    int do_passivedpi = 0, do_block_quic = 0,
        do_fragment_http = 0,
        do_fragment_http_persistent = 0,
        do_fragment_http_persistent_nowait = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_http_allports = 0,
        do_host_mixedcase = 0,
        do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
        do_dns_verb = 0, do_tcp_verb = 0, do_blacklist = 0,
        do_allow_no_sni = 0,
        do_fragment_by_sni = 0,
        do_fragment_in_sni = 0,
        do_reasm = 0,
        do_fake_quic = 0,
        do_fake_packet = 0,
        do_auto_ttl = 0,
        do_wrong_chksum = 0,
        do_wrong_seq = 0,
        do_native_frag = 0, do_reverse_frag = 0;
    unsigned int http_fragment_size = 0;
    unsigned int https_fragment_size = 0;
    unsigned int current_fragment_size = 0;
    unsigned short max_payload_size = 0;
    BYTE should_send_fake = 0;
    BYTE ttl_of_fake_packet = 0;
    BYTE ttl_min_nhops = 0;
    BYTE auto_ttl_1 = 0;
    BYTE auto_ttl_2 = 0;
    BYTE auto_ttl_max = 0;
    uint32_t dnsv4_addr = 0;
    const char *dns_check_domain = NULL;
    struct in6_addr dnsv6_addr = {0};
    struct in6_addr dns_temp_addr = {0};
    uint16_t dnsv4_port = htons(53);
    uint16_t dnsv6_port = htons(53);
    char *host_addr, *useragent_addr, *method_addr;
    const char *fake_quic_name = NULL;
    unsigned int host_len, useragent_len;
    int http_req_fragmented;

    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    unsigned int hdr_value_len;

    // Make sure to search DLLs only in safe path, not in current working dir.
    SetDllDirectory("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);

    if (!running_from_service) {
        running_from_service = 1;
        if (service_register(argc, argv)) {
            /* We've been called as a service. Register service
             * and exit this thread. main() would be called from
             * service.c next time.
             *
             * Note that if service_register() succeedes it does
             * not return until the service is stopped.
             * That is why we should set running_from_service
             * before calling service_register and unset it
             * afterwards.
             */
            return 0;
        }
        running_from_service = 0;
    }

    argv = preset_expand(&argc, argv);
    if (argv == NULL)
        exit(ERROR_DEFAULT);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0)
            return service_install(argc, argv);
        if (strcmp(argv[i], "--remove") == 0)
            return service_remove();
        if (strcmp(argv[i], "--status") == 0)
            return print_status();
        if (strcmp(argv[i], "--probe") == 0) {
            if (i + 1 >= argc) {
                puts("--probe needs a domain name.");
                return 1;
            }
            return probe(argv[i + 1]);
        }
    }

    for (i = 1; i < argc; i++) {
        const char *log = NULL;

        if (strcmp(argv[i], "--log") == 0 && i + 1 < argc)
            log = argv[i + 1];
        else if (strncmp(argv[i], "--log=", 6) == 0)
            log = argv[i] + 6;
        if (log && !open_log(log))
            exit(ERROR_DEFAULT);
    }

    if (filter_string == NULL)
        filter_string = strdup(FILTER_STRING_TEMPLATE);
    if (filter_passive_string == NULL)
        filter_passive_string = strdup(FILTER_PASSIVE_STRING_TEMPLATE);

    printf(
        "AdiosDPI " ADIOSDPI_VERSION
        ": Passive DPI blocker and Active DPI circumvention utility\n\n"
    );

    if (argc == 1) {
        /* enable mode -9 by default */
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:n", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9': // +7+8
                do_block_quic = 1;
                // fall through
            case '8': // +7
                do_wrong_seq = 1;
                // fall through
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'q':
                do_block_quic = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'z': // --port
                /* i is used as a temporary variable here */
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                if (i != 80 && i != 443)
                    add_filter_str(IPPROTO_TCP, i);
                i = 0;
                break;
            case 'D': // --dns-check
                dns_check_domain = optarg;
                break;
            case 'i': // --ip-id
                /* i is used as a temporary variable here */
                i = atousi(optarg, "IP ID parameter error!\n");
                add_ip_id_str(i);
                i = 0;
                break;
            case 'd': // --dns-addr
                if ((inet_pton(AF_INET, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv4_redirect)
                {
                    do_dnsv4_redirect = 1;
                    if (inet_pton(AF_INET, optarg, &dnsv4_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V4_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V4_ADDR);
                break;
            case '!': // --dnsv6-addr
                if ((inet_pton(AF_INET6, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv6_redirect)
                {
                    do_dnsv6_redirect = 1;
                    if (inet_pton(AF_INET6, optarg, dnsv6_addr.s6_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V6_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V6_ADDR);
                break;
            case 'g': // --dns-port
                if (!do_dnsv4_redirect) {
                    puts("--dns-port should be used with --dns-addr!\n"
                        "Make sure you use --dns-addr and pass it before "
                        "--dns-port");
                    exit(ERROR_DNS_V4_PORT);
                }
                dnsv4_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv4_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv4_port);
                }
                dnsv4_port = htons(dnsv4_port);
                break;
            case '@': // --dnsv6-port
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-port should be used with --dnsv6-addr!\n"
                        "Make sure you use --dnsv6-addr and pass it before "
                        "--dnsv6-port");
                    exit(ERROR_DNS_V6_PORT);
                }
                dnsv6_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv6_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv6_port);
                }
                dnsv6_port = htons(dnsv6_port);
                break;
            case 'B': // --dns-backup
                if (!do_dnsv4_redirect) {
                    puts("--dns-backup should be used with --dns-addr!\n"
                        "Make sure you use --dns-addr and pass it before "
                        "--dns-backup");
                    exit(ERROR_DNS_V4_ADDR);
                }
                if (!parse_dns_server(optarg, 0, &dnsv4_backup, dns_backup_text, sizeof(dns_backup_text))) {
                    puts("DNS backup parameter error! Use ADDRESS or ADDRESS:PORT.");
                    exit(ERROR_DNS_V4_ADDR);
                }
                have_dnsv4_backup = 1;
                add_dns_reply_filter(0, dns_backup_text, ntohs(dnsv4_backup.port));
                break;
            case 'C': // --dnsv6-backup
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-backup should be used with --dnsv6-addr!\n"
                        "Make sure you use --dnsv6-addr and pass it before "
                        "--dnsv6-backup");
                    exit(ERROR_DNS_V6_ADDR);
                }
                if (!parse_dns_server(optarg, 1, &dnsv6_backup, dns_backup_text, sizeof(dns_backup_text))) {
                    puts("DNS backup parameter error! Use ADDRESS or [ADDRESS]:PORT.");
                    exit(ERROR_DNS_V6_ADDR);
                }
                have_dnsv6_backup = 1;
                add_dns_reply_filter(1, dns_backup_text, ntohs(dnsv6_backup.port));
                break;
            case 'v':
                do_dns_verb = 1;
                do_tcp_verb = 1;
                break;
            case 'b': // --blacklist
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case ']': // --allow-no-sni
                do_allow_no_sni = 1;
                break;
            case '>': // --frag-by-sni
                do_fragment_by_sni = 1;
                break;
            case 'L': // --log, already opened above
                break;
            case 'Q': // --fake-quic
                do_fake_quic = 1;
                fake_quic_name = optarg;
                break;
            case 'R': // --reasm
                do_reasm = 1;
                break;
            case 'M': // --frag-in-sni
                do_fragment_by_sni = do_fragment_in_sni = 1;
                break;
            case '$': // --set-ttl
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[': // --min-ttl
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+': // --auto-ttl
                do_fake_packet = 1;
                do_auto_ttl = 1;

                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];

                if (optarg) {
                    char *autottl_copy = strdup(optarg);
                    if (strchr(autottl_copy, '-')) {
                        // token "-" found, start X-Y parser
                        char *autottl_current = strtok(autottl_copy, "-");
                        auto_ttl_1 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_2 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_max = atoub(autottl_current, "Set Auto TTL parameter error!");
                    }
                    else {
                        // single digit parser
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%': // --wrong-chksum
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case ')': // --wrong-seq
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*': // --native-frag
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '(': // --reverse-frag
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '|': // --max-payload
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case 'u': // --fake-from-hex
                if (fake_load_from_hex(optarg)) {
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                }
                break;
            case '}': // --fake-with-sni
                if (fake_load_from_sni(optarg)) {
                    printf("WARNING: bad domain name for SNI: %s\n", optarg);
                }
                break;
            case 'j': // --fake-gen
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 't': // --fake-resend
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                if (fakes_resend == 1)
                    puts("WARNING: fake-resend is 1, no resending is in place!");
                else if (!fakes_resend)
                    puts("WARNING: fake-resend is 0, fake packet mode is disabled!");
                else if (fakes_resend > 100)
                    puts("WARNING: fake-resend value is a little too high, don't you think?");
                break;
            case 'x': // --debug-exit
                debug_exit = true;
                break;
            default:
                fputs("Usage: adiosdpi.exe [OPTION...]\n"
                " -p          block passive DPI\n"
                " -q          block QUIC/HTTP3\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI (enables -s, may break sites)\n"
                " -m          mix Host header case (test.com -> tEsT.cOm)\n"
                " -f <value>  set HTTP fragmentation to value\n"
                " -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value\n"
                " -n          do not wait for first segment ACK when -k is enabled\n"
                " -e <value>  set HTTPS fragmentation to value\n"
                " -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)\n"
                " --port        <value>    additional TCP port to perform fragmentation on (and HTTP tricks with -w)\n"
                " --ip-id       <value>    handle additional IP ID (decimal, drop redirects and TCP RSTs with this ID).\n"
                " --dns-addr    <value>    redirect UDPv4 DNS requests to the supplied IPv4 address (experimental)\n"
                " --dns-port    <value>    redirect UDPv4 DNS requests to the supplied port (53 by default)\n"
                " --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address (experimental)\n"
                " --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)\n"
                " --dns-backup  <addr[:port]>  a second DNS server (after --dns-addr): used when the first one\n"
                "                          does not answer, and for a minute after that. --dnsv6-backup is the same\n"
                "                          for IPv6, written [addr]:port.\n"
                " --dns-verb               print verbose DNS redirection messages\n"
                " --dns-check   <domain>   compare the system DNS answer for the domain with a plain DNS server\n"
                "                          (9.9.9.10 port 9953, or --dns-addr and --dns-port) and with DNS over HTTPS\n"
                "                          (1.1.1.1), then exit.\n"
                " --preset      <name>     use a ready set of options: dns, dns-5, dns-9, dns-ttl5,\n"
                "                          dns-ttl3 or ttl3.\n"
                "                          Do not combine with --dns-addr or --dns-port.\n"
                " --install                install AdiosDPI as a Windows service that starts with Windows, using the\n"
                "                          other options given, and start it. File names are turned into full paths.\n"
                " --remove                 stop and remove the AdiosDPI service.\n"
                " --status                 show whether the service runs and whether another WinDivert tool is loaded.\n"
                " --probe       <domain>   try to open the site without any tool and then with each preset,\n"
                "                          and say which one works. Needs a few seconds per candidate.\n"
                " --log         <txtfile>  write everything the program prints to this file instead of the console\n"
                "                          (a new file each run). Use it with --install, a service has no console.\n"
                " --blacklist   <txtfile>  perform circumvention tricks only to host names and subdomains from\n"
                "                          supplied text file (HTTP Host/TLS SNI).\n"
                "                          This option can be supplied multiple times.\n"
                " --reasm                 when the server name is not in the first segment of a ClientHello, hold that segment\n"
                "                          until the next one comes, so --blacklist and --frag-by-sni can use the name.\n"
                "                          Diverts all outgoing HTTPS data, which costs CPU on uploads.\n"
                " --fake-quic  <name>     send a fake QUIC Initial with this server name before every real one, so a DPI\n"
                "                          box that reads QUIC server names sees the fake. The fake has a low TTL (--set-ttl)\n"
                "                          or a wrong checksum (--wrong-chksum, the default). Replaces -q, which blocks QUIC.\n"
                " --allow-no-sni           perform circumvention if TLS SNI can't be detected with --blacklist enabled.\n"
                " --frag-by-sni            if SNI is detected in TLS packet, fragment the packet right before SNI value.\n"
                " --frag-in-sni            same, but fragment in the middle of the SNI value (needs --native-frag,\n"
                "                          which the modes -5 to -9 have).\n"
                , stdout);          /* two strings: one of this size is more than C99 compilers must accept */
                puts(
                " --set-ttl     <value>    activate Fake Request Mode and send it with supplied TTL value.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --auto-ttl    [a1-a2-m]  activate Fake Request Mode, automatically detect TTL and decrease\n"
                "                          it based on a distance. If the distance is shorter than a2, TTL is decreased\n"
                "                          by a2. If it's longer, (a1; a2) scale is used with the distance as a weight.\n"
                "                          If the resulting TTL is more than m(ax), set it to m.\n"
                "                          Default (if set): --auto-ttl 1-4-10. Also sets --min-ttl 3.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --min-ttl     <value>    minimum TTL distance (128/64 - TTL) for which to send Fake Request\n"
                "                          in --set-ttl and --auto-ttl modes.\n"
                " --wrong-chksum           activate Fake Request Mode and send it with incorrect TCP checksum.\n"
                "                          May not work in a VM or with some routers, but is safer than set-ttl.\n"
                "                          Could be combined with --set-ttl\n"
                " --wrong-seq              activate Fake Request Mode and send it with TCP SEQ/ACK in the past.\n"
                " --native-frag            fragment (split) the packets by sending them in smaller packets, without\n"
                "                          shrinking the Window Size. Works faster (does not slow down the connection)\n"
                "                          and better.\n"
                " --reverse-frag           fragment (split) the packets just as --native-frag, but send them in the\n"
                "                          reversed order. Works with the websites which could not handle segmented\n"
                "                          HTTPS TLS ClientHello (because they receive the TCP flow \"combined\").\n"
                " --fake-from-hex <value>  Load fake packets for Fake Request Mode from HEX values (like 1234abcDEF).\n"
                "                          This option can be supplied multiple times, in this case each fake packet\n"
                "                          would be sent on every request in the command line argument order.\n"
                " --fake-with-sni <value>  Generate fake packets for Fake Request Mode with given SNI domain name.\n"
                "                          The packets mimic Mozilla Firefox 130 TLS ClientHello packet\n"
                "                          (with random generated fake SessionID, key shares and ECH grease).\n"
                "                          Can be supplied multiple times for multiple fake packets.\n"
                " --fake-gen <value>       Generate random-filled fake packets for Fake Request Mode, value of them\n"
                "                          (up to 30).\n"
                " --fake-resend <value>    Send each fake packet value number of times.\n"
                "                          Default: 1 (send each packet once).\n"
                " --max-payload [value]    packets with TCP payload data more than [value] won't be processed.\n"
                "                          Use this option to reduce CPU usage by skipping huge amount of data\n"
                "                          (like file transfers) in already established sessions.\n"
                "                          May skip some huge HTTP requests from being processed.\n"
                "                          Default (if set): --max-payload 1200.\n"
                "\n");
                puts("LEGACY modesets:\n"
                " -1          -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode)\n"
                " -2          -p -r -s -f 2 -k 2 -n -e 40 (better speed for HTTPS yet still compatible)\n"
                " -3          -p -r -s -e 40 (better speed for HTTP and HTTPS)\n"
                " -4          -p -r -s (best speed)"
                "\n"
                "Modern modesets (more stable, more compatible, faster):\n"
                " -5          -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
                " -6          -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
                " -7          -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
                " -8          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
                " -9          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (this is the default)\n\n"
                "Note: combination of --wrong-seq and --wrong-chksum generates two different fake packets.\n"
                );
                exit(ERROR_DEFAULT);
        }
    }

    if (dns_check_domain)
        return dns_check(dns_check_domain, do_dnsv4_redirect ? dnsv4_addr : 0,
                         do_dnsv4_redirect ? dnsv4_port : 0);

    if (do_dnsv4_redirect) {
        dns_server_t first = {{dnsv4_addr, 0, 0, 0}, dnsv4_port};
        dns_set_servers(0, &first, have_dnsv4_backup ? &dnsv4_backup : NULL);
    }
    if (do_dnsv6_redirect) {
        dns_server_t first;
        memcpy(first.ip, dnsv6_addr.s6_addr, sizeof(first.ip));
        first.port = dnsv6_port;
        dns_set_servers(1, &first, have_dnsv6_backup ? &dnsv6_backup : NULL);
    }

    if (do_fake_quic) {
        /* The fake goes with the real Initial, so QUIC must not be blocked as well. */
        do_block_quic = 0;
        if (fake_quic_load(fake_quic_name)) {
            printf("Can't build a fake QUIC packet for the name \"%s\".\n", fake_quic_name);
            exit(ERROR_DEFAULT);
        }
        add_quic_filter();
        printf("Fake QUIC Initial with the name %s before each real one (QUIC is not blocked)\n", fake_quic_name);
    }

    if (!http_fragment_size)
        http_fragment_size = 2;
    if (!https_fragment_size)
        https_fragment_size = 2;
    if (!auto_ttl_1)
        auto_ttl_1 = 1;
    if (!auto_ttl_2)
        auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops)
            ttl_min_nhops = 3;
        if (!auto_ttl_max)
            auto_ttl_max = 10;
    }

    printf("Block passive: %d\n"                    /* 1 */
           "Block QUIC/HTTP3: %d\n"                 /* 1 */
           "Fragment HTTP: %u\n"                    /* 2 */
           "Fragment persistent HTTP: %u\n"         /* 3 */
           "Fragment HTTPS: %u\n"                   /* 4 */
           "Fragment by SNI: %d\n"                  /* 5 */
           "Native fragmentation (splitting): %d\n" /* 6 */
           "Fragments sending in reverse: %d\n"     /* 7 */
           "hoSt: %d\n"                             /* 8 */
           "Host no space: %d\n"                    /* 9 */
           "Additional space: %d\n"                 /* 10 */
           "Mix Host: %d\n"                         /* 11 */
           "HTTP AllPorts: %d\n"                    /* 12 */
           "HTTP Persistent Nowait: %d\n"           /* 13 */
           "DNS redirect: %d\n"                     /* 14 */
           "DNSv6 redirect: %d\n"                   /* 15 */
           "Allow missing SNI: %d\n"                /* 16 */
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"  /* 17 */
           "Fake requests, wrong checksum: %d\n"    /* 18 */
           "Fake requests, wrong SEQ/ACK: %d\n"     /* 19 */
           "Fake requests, custom payloads: %d\n"   /* 20 */
           "Fake requests, resend: %d\n"            /* 21 */
           "Max payload size: %hu\n",               /* 22 */
           do_passivedpi, do_block_quic,                          /* 1 */
           (do_fragment_http ? http_fragment_size : 0),           /* 2 */
           (do_fragment_http_persistent ? http_fragment_size : 0),/* 3 */
           (do_fragment_https ? https_fragment_size : 0),         /* 4 */
           do_fragment_by_sni,    /* 5 */
           do_native_frag,        /* 6 */
           do_reverse_frag,       /* 7 */
           do_host,               /* 8 */
           do_host_removespace,   /* 9 */
           do_additional_space,   /* 10 */
           do_host_mixedcase,     /* 11 */
           do_http_allports,      /* 12 */
           do_fragment_http_persistent_nowait, /* 13 */
           do_dnsv4_redirect,                  /* 14 */
           do_dnsv6_redirect,                  /* 15 */
           do_allow_no_sni,                    /* 16 */
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),  /* 17 */
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum, /* 18 */
           do_wrong_seq,    /* 19 */
           fakes_count,     /* 20 */
           fakes_resend,    /* 21 */
           max_payload_size /* 22 */
          );

    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag) {
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    }

    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }

    if (max_payload_size)
        add_maxpayloadsize_str(max_payload_size);
    /* Without any TCP feature the driver has no TCP packet to hand us. */
    {
        struct filter_features features = {
            .passive = do_passivedpi,
            .tcp = do_passivedpi || do_fake_packet || do_native_frag || do_host ||
                   do_host_removespace || do_host_mixedcase || do_fragment_http ||
                   do_fragment_https || do_fragment_http_persistent,
            /* A server's SYN+ACK is used to shrink its window and to measure its distance. */
            .synack = (!do_native_frag && (do_fragment_http || do_fragment_https)) ||
                      (do_fake_packet && (do_auto_ttl || ttl_min_nhops)),
            .http_all = do_http_allports || do_reasm,  /* the second segment of a ClientHello is not a handshake record */
            /* Window size fragmentation makes the client send the rest of a method alone. */
            .http_requests = !(do_fragment_http && !do_native_frag),
        };
        finalize_filter_strings(&features);
    }
    {
        HANDLE scan = CreateThread(NULL, 0, finish_startup, NULL, 0, NULL);
        if (scan)
            CloseHandle(scan);
    }
    puts("\nOpening filter");
    filter_num = 0;

    if (do_passivedpi) {
        /* IPv4 only filter for inbound RST packets with ID [0x0; 0xF] */
        filters[filter_num] = init(
            filter_passive_string,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }

    if (do_block_quic) {
        filters[filter_num] = init(
            FILTER_QUIC_INITIAL,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }

    /* 
     * IPv4 & IPv6 filter for inbound HTTP redirection packets and
     * active DPI circumvention
     */
    filters[filter_num] = init(filter_string, 0);

    w_filter = filters[filter_num];
    filter_num++;

    for (i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }
    if (debug_exit) {
        printf("Debug Exit\n");
        exit(EXIT_SUCCESS);
    }
    printf("Filter activated, AdiosDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    unsigned int recv_failures = 0;
    struct reasm_result reasm;

    while (1) {
        UINT addr_len = 0, batch_len = 0, batch_rem = 0;
        char *batch_pkt = NULL;
        int batch_count = 0, batch_idx = 0, have_packet = 0;

        memset(&reasm, 0, sizeof(reasm));
        if (reasm_next(packet_buf, sizeof(packet_buf), &packetLen, &addr, &reasm)) {
            recv_failures = 0;
            have_packet = 1;
        }
        else {
            addr_len = sizeof(batch_addrs);
            if (!WinDivertRecvEx(w_filter, batch, sizeof(batch), &batch_len, 0,
                                 batch_addrs, &addr_len, NULL)) {
                DWORD err = GetLastError();
                /* The handle was shut down: this is the normal way out. */
                if (exiting || err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE)
                    break;
                /* Anything else costs one packet at most, and TCP resends it. */
                if (++recv_failures > 100) {
                    printf("Too many receive errors (last error %lu), giving up.\n", err);
                    break;
                }
                if (recv_failures == 1)
                    printf("Error receiving a packet (error %lu), continuing.\n", err);
                continue;
            }
            recv_failures = 0;
            reasm_expire(w_filter);
            batch_count = (int)(addr_len / sizeof(WINDIVERT_ADDRESS));
            batch_pkt = batch;
            batch_rem = batch_len;
        }

        for (;;) {
            /* A joined ClientHello goes out in order, before the rest of the batch. */
            if (!have_packet &&
                !reasm_next(packet_buf, sizeof(packet_buf), &packetLen, &addr, &reasm)) {
                if (batch_idx >= batch_count || batch_rem == 0)
                    break;
                packetLen = batch_packet_len(batch_pkt, batch_rem);
                packet = batch_pkt;
                addr = batch_addrs[batch_idx++];
                batch_pkt += packetLen;
                batch_rem -= packetLen;
            }
            have_packet = 0;

            debug("Got %s packet, len=%d!\n", addr.Outbound ? "outbound" : "inbound",
                   packetLen);
            should_reinject = 1;
            should_recalc_checksum = 0;
            sni_ok = 0;

            ppIpHdr = (PWINDIVERT_IPHDR)NULL;
            ppIpV6Hdr = (PWINDIVERT_IPV6HDR)NULL;
            ppTcpHdr = (PWINDIVERT_TCPHDR)NULL;
            ppUdpHdr = (PWINDIVERT_UDPHDR)NULL;
            packet_v4 = packet_v6 = 0;
            packet_type = unknown;

            // Parse network packet and set it's type
            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr, &packet_data, &packet_dataLen,
                NULL, NULL))
            {
                if (ppIpHdr) {
                    packet_v4 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv4_tcp;
                        if (packet_data) {
                            packet_type = ipv4_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv4_udp_data;
                    }
                }

                else if (ppIpV6Hdr) {
                    packet_v6 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv6_tcp;
                        if (packet_data) {
                            packet_type = ipv6_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv6_udp_data;
                    }
                }
            }

            debug("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);

            if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) {
                //printf("Got parsed packet, len=%d!\n", packet_dataLen);
                /* Got a TCP packet WITH DATA */

                /* The segment after a held back ClientHello: both go on, in order, once the name is known. */
                if (do_reasm && addr.Outbound && reasm_join(packet, packetLen, &addr))
                    continue;

                /* Handle INBOUND packet with data and find HTTP REDIRECT in there */
                if (!addr.Outbound && packet_dataLen > 16) {
                    /* If INBOUND packet with DATA (tcp.Ack) */

                    /* Drop packets from filter with HTTP 30x Redirect */
                    if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        if (packet_v4) {
                            //printf("Dropping HTTP Redirect packet!\n");
                            should_reinject = 0;
                        }
                        else if (packet_v6 && WINDIVERT_IPV6HDR_GET_FLOWLABEL(ppIpV6Hdr) == 0x0) {
                                /* Contrary to IPv4 where we get only packets with IP ID 0x0-0xF,
                                 * for IPv6 we got all the incoming data packets since we can't
                                 * filter them in a driver.
                                 *
                                 * Handle only IPv6 Flow Label == 0x0 for now
                                 */
                                //printf("Dropping HTTP Redirect packet!\n");
                                should_reinject = 0;
                        }
                    }
                }
                /* Handle OUTBOUND packet on port 443, search for something that resembles
                 * TLS handshake, send fake request.
                 */
                else if (addr.Outbound &&
                        ((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
                         packet_dataLen > 16) &&
                         ppTcpHdr->DstPort != htons(80) &&
                         (do_fake_packet || do_native_frag)
                        )
                {
                    /**
                     * In case of Window Size fragmentation=2, we'll receive only 2 byte packet.
                     * But if the packet is more than 2 bytes, check ClientHello byte.
                    */
                    if (tls_is_handshake_record(packet_data, packet_dataLen))
                    {
                        if (do_blacklist || do_fragment_by_sni) {
                            if (reasm.known) {
                                /* A held back ClientHello: the name was looked up in both of its segments. */
                                sni_ok = reasm.sni_ok;
                                host_addr = reasm.host;
                                host_len = reasm.host_len;
                                if (do_tcp_verb) {
                                    if (sni_ok)
                                        printf("Joined a ClientHello of two segments, server name %.*s\n",
                                               (int)host_len, host_addr);
                                    else
                                        printf("Joined a ClientHello of two segments, no server name in it\n");
                                }
                            } else {
                                sni_ok = tls_extract_sni(packet_data, packet_dataLen,
                                            &host_addr, &host_len);
                                if (!sni_ok && do_reasm && tls_hello_incomplete(packet_data, packet_dataLen) &&
                                    reasm_hold(packet, packetLen, &addr))
                                    continue;
                            }
                        }
                        if (
                             (do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len)
                             ) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (!do_blacklist)
                           )
                        {
#ifdef DEBUG
                            char lsni[HOST_MAXLEN + 1] = {0};
                            tls_extract_sni(packet_data, packet_dataLen,
                                        &host_addr, &host_len);
                            memcpy(lsni, host_addr, host_len);
                            printf("Blocked HTTPS website SNI: %s\n", lsni);
#endif
                            if (do_fake_packet) {
                                flush_tx(w_filter);
                                TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
                            }
                            if (do_native_frag) {
                                // Signal for native fragmentation code handler
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                }
                /* Handle OUTBOUND packet on port 80, search for Host header */
                else if (addr.Outbound && 
                        packet_dataLen > 16 &&
                        (do_http_allports ? 1 : (ppTcpHdr->DstPort == htons(80))) &&
                        find_http_method_end(packet_data,
                                             (do_fragment_http ? http_fragment_size : 0u),
                                             &http_req_fragmented) &&
                        (do_host || do_host_removespace ||
                        do_host_mixedcase || do_fragment_http_persistent ||
                        do_fake_packet))
                {

                    /* Find Host header */
                    if (find_header_and_get_info(packet_data, packet_dataLen,
                        http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                        hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                        (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
                    {
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;
#ifdef DEBUG
                        char lhost[HOST_MAXLEN + 1] = {0};
                        memcpy(lhost, host_addr, host_len);
                        printf("Blocked HTTP website Host: %s\n", lhost);
#endif

                        if (do_native_frag) {
                            // Signal for native fragmentation code handler
                            should_recalc_checksum = 1;
                        }

                        if (do_fake_packet) {
                            flush_tx(w_filter);
                            TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_http_request);
                        }

                        if (do_host_mixedcase) {
                            mix_case(host_addr, host_len);
                            should_recalc_checksum = 1;
                        }

                        if (do_host) {
                            /* Replace "Host: " with "hoSt: " */
                            memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                            should_recalc_checksum = 1;
                            //printf("Replaced Host header!\n");
                        }

                        /* If removing space between host header and its value
                         * and adding additional space between Method and Request-URI */
                        if (do_additional_space && do_host_removespace) {
                            /* End of "Host:" without trailing space */
                            method_addr = find_http_method_end(packet_data,
                                                            (do_fragment_http ? http_fragment_size : 0),
                                                            NULL);

                            if (method_addr) {
                                memmove(method_addr + 1, method_addr,
                                        (size_t)(host_addr - method_addr - 1));
                                should_recalc_checksum = 1;
                            }
                        }
                        /* If just removing space between host header and its value */
                        else if (do_host_removespace) {
                            if (find_header_and_get_info(packet_data, packet_dataLen,
                                                        http_useragent_find, &hdr_name_addr,
                                                         &hdr_value_addr, &hdr_value_len))
                            {
                                useragent_addr = hdr_value_addr;
                                useragent_len = hdr_value_len;

                                /* We move Host header value by one byte to the left and then
                                 * "insert" stolen space to the end of User-Agent value because
                                 * some web servers are not tolerant to additional space in the
                                 * end of Host header.
                                 *
                                 * Nothing is done if User-Agent header is missing.
                                 */
                                if (useragent_addr && useragent_len > 0) {
                                    /* useragent_addr is in the beginning of User-Agent value */

                                    if (useragent_addr > host_addr) {
                                        /* Move one byte to the LEFT from "Host:"
                                        * to the end of User-Agent
                                        */
                                        memmove(host_addr - 1, host_addr,
                                                (size_t)(useragent_addr + useragent_len - host_addr));
                                        host_addr -= 1;
                                        /* Put space in the end of User-Agent header */
                                        *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                        should_recalc_checksum = 1;
                                        //printf("Replaced Host header!\n");
                                    }
                                    else {
                                        /* User-Agent goes BEFORE Host header */

                                        /* Move one byte to the RIGHT from the end of User-Agent
                                        * to the "Host:"
                                        */
                                        memmove(useragent_addr + useragent_len + 1,
                                                useragent_addr + useragent_len,
                                                (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                        /* Put space in the end of User-Agent header */
                                        *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                        should_recalc_checksum = 1;
                                        //printf("Replaced Host header!\n");
                                    }
                                } /* if (host_len <= HOST_MAXLEN && useragent_addr) */
                            } /* if (find_header_and_get_info http_useragent) */
                        } /* else if (do_host_removespace) */
                    } /* if (find_header_and_get_info http_host) */
                } /* Handle OUTBOUND packet with data */

                /*
                * should_recalc_checksum mean we have detected a packet to handle and
                * modified it in some way.
                * Handle native fragmentation here, incl. sending the packet.
                */
                if (should_reinject && should_recalc_checksum && do_native_frag)
                {
                    current_fragment_size = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        current_fragment_size = http_fragment_size;
                    }
                    else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        if (do_fragment_by_sni && sni_ok && !reasm.known) {   /* a name in the next segment is no place to split this one */
                            current_fragment_size = (unsigned int)(host_addr - (char *)packet_data);
                            if (do_fragment_in_sni)
                                current_fragment_size += host_len / 2;
                        } else {
                            current_fragment_size = https_fragment_size;
                        }
                    }

                    if (current_fragment_size) {
                        flush_tx(w_filter);
                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen,packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, do_reverse_frag);

                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen,packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, !do_reverse_frag);
                        continue;
                    }
                }
            } /* Handle TCP packet with data */

            /* Else if we got TCP packet without data */
            else if (packet_type == ipv4_tcp || packet_type == ipv6_tcp) {
                /* If we got INBOUND SYN+ACK packet */
                if (!addr.Outbound &&
                    ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1) {
                    //printf("Changing Window Size!\n");
                    /*
                     * Window Size is changed even if do_fragment_http_persistent
                     * is enabled as there could be non-HTTP data on port 80
                     */

                    if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                        if (!((packet_v4 && tcp_handle_incoming(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        0, ppIpHdr->TTL))
                            ||
                            (packet_v6 && tcp_handle_incoming((uint32_t*)&ppIpV6Hdr->SrcAddr,
                                        (uint32_t*)&ppIpV6Hdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        1, ppIpV6Hdr->HopLimit))))
                        {
                            if (do_tcp_verb)
                                puts("[TCP WARN] Can't add TCP connection record.");
                        }
                    }

                    if (!do_native_frag) {
                        if (do_fragment_http && ppTcpHdr->SrcPort == htons(80)) {
                            change_window_size(ppTcpHdr, http_fragment_size);
                            should_recalc_checksum = 1;
                        }
                        else if (do_fragment_https && ppTcpHdr->SrcPort != htons(80)) {
                            change_window_size(ppTcpHdr, https_fragment_size);
                            should_recalc_checksum = 1;
                        }
                    }
                }
            }

            /* Else if we got an outgoing QUIC Initial: the fake one goes first, the real one below */
            else if (do_fake_quic && addr.Outbound &&
                     (packet_type == ipv4_udp_data || packet_type == ipv6_udp_data) &&
                     ppUdpHdr->DstPort == htons(443) &&
                     quic_is_initial((const unsigned char *)packet_data, packet_dataLen))
            {
                int resend;

                if (do_tcp_verb)
                    printf("QUIC Initial: sending %d fake packet(s) first\n", fakes_resend);
                flush_tx(w_filter);
                /* Like the TCP fakes: --set-ttl and --wrong-chksum; with neither, the checksum is wrong. */
                for (resend = 0; resend < fakes_resend; resend++)
                    if (send_fake_quic(w_filter, &addr, packet, packetLen, packet_v6,
                                       ttl_of_fake_packet, (BYTE)(do_wrong_chksum || !ttl_of_fake_packet)) &&
                        do_tcp_verb)
                        printf("Can't send the fake QUIC packet (error %lu)\n", GetLastError());
            }

            /* Else if we got UDP packet with data */
            else if ((do_dnsv4_redirect && (packet_type == ipv4_udp_data)) ||
                     (do_dnsv6_redirect && (packet_type == ipv6_udp_data)))
            {
                if (!addr.Outbound) {
                    if ((packet_v4 && dns_handle_incoming(&ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 0,
                                        &ppIpHdr->SrcAddr, ppUdpHdr->SrcPort))
                        ||
                        (packet_v6 && dns_handle_incoming(ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 1,
                                        ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort)))
                    {
                        /* Changing source IP and port to the values
                         * from DNS conntrack */
                        if (packet_v4)
                            ppIpHdr->SrcAddr = dns_conn_info.dstip[0];
                        else if (packet_v6)
                            ipv6_copy_addr(ppIpV6Hdr->SrcAddr, dns_conn_info.dstip);
                        ppUdpHdr->DstPort = dns_conn_info.srcport;
                        ppUdpHdr->SrcPort = dns_conn_info.dstport;
                        should_recalc_checksum = 1;
                    }
                    else {
                        if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
                            should_reinject = 0;

                        if (do_dns_verb && !should_reinject) {
                            printf("[DNS] Error handling incoming packet: srcport = %hu, dstport = %hu\n",
                               ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                        }
                    }
                }

                else if (addr.Outbound) {
                    if ((packet_v4 && dns_handle_outgoing(&ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
                                        &ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen, 0, &dns_target))
                        ||
                        (packet_v6 && dns_handle_outgoing(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
                                        ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen, 1, &dns_target)))
                    {
                        /* Changing destination IP and port to the server
                         * chosen from the configuration */
                        if (packet_v4) {
                            ppIpHdr->DstAddr = dns_target.ip[0];
                            ppUdpHdr->DstPort = dns_target.port;
                        }
                        else if (packet_v6) {
                            ipv6_copy_addr(ppIpV6Hdr->DstAddr, dns_target.ip);
                            ppUdpHdr->DstPort = dns_target.port;
                        }
                        should_recalc_checksum = 1;
                    }
                    else {
                        if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
                            should_reinject = 0;

                        if (do_dns_verb && !should_reinject) {
                            printf("[DNS] Error handling outgoing packet: srcport = %hu, dstport = %hu\n",
                               ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                        }
                    }
                }
            }

            if (should_reinject) {
                //printf("Re-injecting!\n");
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                queue_tx(w_filter, packet, packetLen, &addr);
            }
        }
        flush_tx(w_filter);
    }
    deinit_all();
    return 0;
}
