/*
 * Option presets for AdiosDPI: short names for option sets that are known to
 * work, so nobody has to remember a resolver address and a non-standard port.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "preset.h"

/* Plain UDP DNS on a non-standard port, which ISP resolvers do not intercept. */
#define DNS_OPTIONS "--dns-addr", "77.88.8.8", "--dns-port", "1253", \
                    "--dnsv6-addr", "2a02:6b8::feed:0ff", "--dnsv6-port", "1253"

#define MAX_PRESET_OPTIONS 10

static const struct {
    const char *name;
    const char *description;
    const char *options[MAX_PRESET_OPTIONS];
} presets[] = {
    {"dns",   "fix DNS poisoning only, no packet tricks",     {DNS_OPTIONS, NULL}},
    {"dns-5", "DNS fix + mode -5 (modern, auto TTL)",         {"-5", DNS_OPTIONS, NULL}},
    {"dns-9", "DNS fix + mode -9 (all fakes, blocks QUIC)",   {"-9", DNS_OPTIONS, NULL}},
};
#define PRESET_COUNT (sizeof(presets) / sizeof(*presets))

static void list_presets(void) {
    size_t i;
    puts("Available presets:");
    for (i = 0; i < PRESET_COUNT; i++)
        printf("  %-6s %s\n", presets[i].name, presets[i].description);
}

char **preset_expand(int *argc, char **argv) {
    char **out = malloc(sizeof(char *) * ((size_t)*argc * MAX_PRESET_OPTIONS + 1));
    int n = 0, i;

    if (!out)
        return NULL;
    out[n++] = argv[0];
    for (i = 1; i < *argc; i++) {
        const char *name = NULL;
        size_t p, o;

        if (strcmp(argv[i], "--preset") == 0) {
            if (i + 1 >= *argc) {
                puts("--preset needs a name.");
                list_presets();
                free(out);
                return NULL;
            }
            name = argv[++i];
        }
        else if (strncmp(argv[i], "--preset=", 9) == 0) {
            name = argv[i] + 9;
        }
        if (!name) {
            out[n++] = argv[i];
            continue;
        }

        for (p = 0; p < PRESET_COUNT && strcmp(presets[p].name, name) != 0; p++)
            ;
        if (p == PRESET_COUNT) {
            printf("Unknown preset \"%s\".\n", name);
            list_presets();
            free(out);
            return NULL;
        }
        for (o = 0; presets[p].options[o]; o++)
            out[n++] = (char *)presets[p].options[o];
    }
    out[n] = NULL;
    *argc = n;
    return out;
}
