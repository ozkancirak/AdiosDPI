/*
 * Cut positions for splitting a ClientHello (see splitpos.h).
 */

#include <stdlib.h>
#include <string.h>
#include "splitpos.h"

enum { ABS, FROM_END, HOST, ENDHOST, SLD, ENDSLD, MIDSLD, SNIEXT };

static const struct {
    const char *name;
    int kind;
} markers[] = {
    {"endhost", ENDHOST}, {"endsld", ENDSLD}, {"midsld", MIDSLD}, {"sniext", SNIEXT},
    {"host", HOST}, {"sld", SLD},
};

/* One word of the list: a number, or a marker with an optional +N / -N. */
static int parse_item(const char *word, size_t n, int *kind, int *add) {
    char *end;
    size_t i, len;
    long v;

    *add = 0;
    if (n && ((word[0] >= '0' && word[0] <= '9') || word[0] == '-')) {
        v = strtol(word, &end, 10);
        if (end != word + n || v < -65535 || v > 65535 || v == 0)
            return 0;
        *kind = v < 0 ? FROM_END : ABS;
        *add = (int)v;
        return 1;
    }
    for (i = 0; i < sizeof(markers) / sizeof(*markers); i++) {
        len = strlen(markers[i].name);
        if (n < len || strncmp(word, markers[i].name, len) != 0)
            continue;
        if (n == len) {
            *kind = markers[i].kind;
            return 1;
        }
        if (word[len] != '+' && word[len] != '-')
            continue;
        v = strtol(word + len, &end, 10);
        if (end != word + n || v < -65535 || v > 65535)
            return 0;
        *kind = markers[i].kind;
        *add = (int)v;
        return 1;
    }
    return 0;
}

int split_parse(const char *text, struct split_spec *spec) {
    const char *p = text;

    spec->count = 0;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);

        if (spec->count == SPLIT_MAX ||
            !parse_item(p, n, &spec->item[spec->count].kind, &spec->item[spec->count].add))
            return 0;
        spec->count++;
        p += n;
        if (*p == ',')
            p++;
    }
    return spec->count > 0;
}

/* The second-level domain of host: its last two labels' first one (a single label counts as its own). */
static void find_sld(const char *host, unsigned int host_len, unsigned int *start, unsigned int *end) {
    unsigned int last_dot = host_len, prev_dot = host_len, i;

    for (i = host_len; i-- > 0;) {
        if (host[i] != '.')
            continue;
        if (last_dot == host_len) {
            last_dot = i;
        }
        else {
            prev_dot = i;
            break;
        }
    }
    if (last_dot == host_len) {         /* no dot: the whole name */
        *start = 0;
        *end = host_len;
        return;
    }
    *start = prev_dot == host_len ? 0 : prev_dot + 1;
    *end = last_dot;
}

static int cmp_uint(const void *a, const void *b) {
    unsigned int x = *(const unsigned int *)a, y = *(const unsigned int *)b;

    return x < y ? -1 : x > y;
}

int split_resolve(const struct split_spec *spec, const char *data, unsigned int len,
                  const char *host, unsigned int host_len, unsigned int *out) {
    long host_off = -1, host_size = (long)host_len, sld_s = 0, sld_e = 0, pos;
    unsigned int sld_start = 0, sld_end = 0, n = 0, i, k;

    if (host && host >= data && (size_t)(host - data) + host_len <= len) {
        host_off = (long)(host - data);
        find_sld(host, host_len, &sld_start, &sld_end);
        sld_s = (long)sld_start;
        sld_e = (long)sld_end;
    }
    for (i = 0; i < (unsigned int)spec->count; i++) {
        int kind = spec->item[i].kind, add = spec->item[i].add;

        if (kind == ABS)
            pos = add;
        else if (kind == FROM_END)
            pos = (long)len + add;
        else if (host_off < 0)
            continue;
        else if (kind == HOST)
            pos = host_off + add;
        else if (kind == ENDHOST)
            pos = host_off + host_size + add;
        else if (kind == SLD)
            pos = host_off + sld_s + add;
        else if (kind == ENDSLD)
            pos = host_off + sld_e + add;
        else if (kind == MIDSLD)
            pos = host_off + sld_s + (sld_e - sld_s) / 2 + add;
        else                            /* SNIEXT: 2 bytes list length, 1 byte name type, 2 bytes name length */
            pos = host_off - 5 + add;
        if (pos > 0 && pos < (long)len)
            out[n++] = (unsigned int)pos;
    }
    qsort(out, n, sizeof(*out), cmp_uint);
    for (i = k = 0; i < n; i++)         /* the same place twice is one cut */
        if (k == 0 || out[i] != out[k - 1])
            out[k++] = out[i];
    return (int)k;
}
