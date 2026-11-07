#ifndef _SPLITPOS_H
#define _SPLITPOS_H

/*
 * Where to cut the first packet of a TLS connection: a list such as "1,midsld,sniext+1,endhost-2,-10".
 *
 *   N            N bytes from the start of the data         -N   N bytes before its end
 *   host         the first byte of the server name          endhost   the byte after its last
 *   sld          the start of the second-level domain       endsld    the byte after it
 *   midsld       the middle of the second-level domain
 *   sniext       the start of the data of the server_name extension (the 2 bytes of its list length)
 *
 * A name marker can be followed by +N or -N. Name markers need the server name; a position
 * that can't be worked out is left out.
 */

#define SPLIT_MAX 8

struct split_spec {
    int count;
    struct {
        int kind;
        int add;
    } item[SPLIT_MAX];
};

/* Reads the list. Returns 1, or 0 when there is a word it does not know or too many of them. */
int split_parse(const char *text, struct split_spec *spec);

/*
 * The cut positions for this data, in order and without duplicates, all between 0 and len
 * exclusive. host and host_len are the server name found in data (NULL when there is none).
 * out has room for SPLIT_MAX. Returns how many there are.
 */
int split_resolve(const struct split_spec *spec, const char *data, unsigned int len,
                  const char *host, unsigned int host_len, unsigned int *out);

#endif
