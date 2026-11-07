extern int fakes_count;
extern int fakes_resend;
/* 1: send one more fake that carries a TCP MD5 signature option with a wrong hash (--md5sig). */
extern int fake_md5sig;
int send_fake_http_request(const HANDLE w_filter,
                                  const PWINDIVERT_ADDRESS addr,
                                  const char *pkt,
                                  const UINT packetLen,
                                  const BOOL is_ipv6,
                                  const BYTE set_ttl,
                                  const BYTE set_checksum,
                                  const BYTE set_seq
                                 );
int send_fake_https_request(const HANDLE w_filter,
                                   const PWINDIVERT_ADDRESS addr,
                                   const char *pkt,
                                   const UINT packetLen,
                                   const BOOL is_ipv6,
                                   const BYTE set_ttl,
                                   const BYTE set_checksum,
                                   const BYTE set_seq
                                 );
/*
 * Fake QUIC Initial: builds one for the server name, and sends a copy of it in place of the payload of
 * pkt (an outgoing QUIC Initial) before the real one. A DPI box can read its name, the server never
 * sees it: its TTL is too low to get there, or its UDP checksum is wrong.
 */
int fake_quic_load(const char *domain_name);
int send_fake_quic(const HANDLE w_filter,
                   const PWINDIVERT_ADDRESS addr,
                   const char *pkt,
                   const UINT packetLen,
                   const BOOL is_ipv6,
                   const BYTE set_ttl,
                   const BYTE set_checksum
                  );
int fake_load_from_hex(const char *data);
int fake_load_from_sni(const char *domain_name);
int fake_load_random(unsigned int count, unsigned int maxsize);
