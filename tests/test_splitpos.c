#include <stdio.h>
#include <string.h>
#include "splitpos.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static int run(const char *list, const char *data, unsigned len, const char *host, unsigned hlen, unsigned *out) {
    struct split_spec s;
    if (!split_parse(list, &s)) return -1;
    return split_resolve(&s, data, len, host, hlen, out);
}

int main(void) {
    char data[200];
    unsigned out[SPLIT_MAX], n;
    struct split_spec s;
    const char *h1 = "cdn.discordapp.com";

    memset(data, 'x', sizeof(data));
    memcpy(data + 100, h1, 18);

    /* parsing */
    CHECK(split_parse("1,midsld,sniext+1,endhost-2,-10", &s) && s.count == 5);
    CHECK(!split_parse("", &s));
    CHECK(!split_parse("abc", &s));
    CHECK(!split_parse("1,,2", &s));
    CHECK(!split_parse("0", &s));
    CHECK(!split_parse("host+x", &s));
    CHECK(!split_parse("1,2,3,4,5,6,7,8,9", &s));
    CHECK(split_parse("1,2,3,4,5,6,7,8", &s) && s.count == 8);

    /* cdn.discordapp.com at 100: host 100, endhost 118, sld 104..114, mid 109, sniext 95 */
    n = (unsigned)run("1,midsld,sniext+1,endhost-2,-10", data, 200, data + 100, 18, out);
    CHECK(n == 5 && out[0] == 1 && out[1] == 96 && out[2] == 109 && out[3] == 116 && out[4] == 190);
    n = (unsigned)run("host,endhost,sld,endsld,sniext", data, 200, data + 100, 18, out);
    CHECK(n == 5 && out[0] == 95 && out[1] == 100 && out[2] == 104 && out[3] == 114 && out[4] == 118);
    /* no server name: only the numbers */
    n = (unsigned)run("1,midsld,host,-10", data, 200, NULL, 0, out);
    CHECK(n == 2 && out[0] == 1 && out[1] == 190);
    /* duplicates and out of range */
    n = (unsigned)run("5,5,200,-300,199", data, 200, NULL, 0, out);
    CHECK(n == 2 && out[0] == 5 && out[1] == 199);
    /* a name that is not inside the data is ignored */
    n = (unsigned)run("midsld,3", data, 200, data + 198, 18, out);
    CHECK(n == 1 && out[0] == 3);
    /* two labels, one label */
    memcpy(data + 50, "discord.com", 11);
    n = (unsigned)run("midsld,endsld,sld", data, 200, data + 50, 11, out);
    CHECK(n == 3 && out[0] == 50 + 0 && out[1] == 53 && out[2] == 57);   /* sld at 50 itself is position 50, kept */
    memcpy(data + 60, "localhost", 9);
    n = (unsigned)run("midsld", data, 200, data + 60, 9, out);
    CHECK(n == 1 && out[0] == 64);
    /* a cut at the very start or end is no cut */
    n = (unsigned)run("host-100,endhost+500", data, 200, data + 100, 18, out);
    CHECK(n == 0);

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
