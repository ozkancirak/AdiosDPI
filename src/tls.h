#ifndef _TLS_H
#define _TLS_H

/*
 * Does the data start like a TLS handshake record (a ClientHello comes in one)?
 * When only 2 bytes are there, as after splitting at 2, the version's last byte is missing.
 */
int tls_is_handshake_record(const char *data, unsigned int len);

/*
 * Is this the start of a ClientHello that goes on in the next segment?
 */
int tls_hello_incomplete(const char *data, unsigned int len);

/*
 * Finds the server name (SNI) in a ClientHello. On success the name is at *host in the
 * data itself, *host_len long, and it is not null terminated. A name cut off by the end
 * of the data does not count.
 */
int tls_extract_sni(const char *data, unsigned int len, char **host, unsigned int *host_len);

#endif
