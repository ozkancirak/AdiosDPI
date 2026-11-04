/*
 * Blacklist for AdiosDPI HTTP DPI circumvention tricks
 *
 * This is a simple domain hash table.
 * Domain records are added from a text file, where every
 * domain is separated with a new line.
 * The files are read again when one of them changes.
 */
#include <windows.h>
#include <stdio.h>
#include "adiosdpi.h"
#include "utils/uthash.h"
#include "utils/getline.h"

typedef struct blackwhitelist_record {
    const char *host;
    UT_hash_handle hh;   /* makes this structure hashable */
} blackwhitelist_record_t;

static blackwhitelist_record_t *blackwhitelist = NULL;

#define MAX_LISTS 16
#define RELOAD_INTERVAL_MS 3000

/* What a file looked like when it was read. The size also catches an edit within the same clock tick. */
struct stamp {
    FILETIME time;
    DWORD size;
};

/* The files the table was built from (more than MAX_LISTS are loaded but not watched). */
static struct {
    char path[MAX_PATH];
    struct stamp stamp;
} lists[MAX_LISTS];
static int list_count;
static ULONGLONG next_check;

static int check_get_hostname(const char *host) {
    blackwhitelist_record_t *tmp_record = NULL;
    if (!blackwhitelist) return FALSE;

    HASH_FIND_STR(blackwhitelist, host, tmp_record);
    if (tmp_record) {
        debug("check_get_hostname found host\n");
        return TRUE;
    }
    debug("check_get_hostname host not found\n");
    return FALSE;
}

static int add_hostname(const char *host) {
    if (!host)
        return FALSE;

    blackwhitelist_record_t *tmp_record = malloc(sizeof(blackwhitelist_record_t));
    char *host_c = NULL;

    if (!check_get_hostname(host)) {
        host_c = strdup(host);
        tmp_record->host = host_c;
        HASH_ADD_KEYPTR(hh, blackwhitelist, tmp_record->host,
                        strlen(tmp_record->host), tmp_record);
        debug("Added host %s\n", host_c);
        return TRUE;
    }
    debug("Not added host %s\n", host);
    free(tmp_record);
    if (host_c)
        free(host_c);
    return FALSE;
}

static void free_table(blackwhitelist_record_t **table) {
    blackwhitelist_record_t *rec, *tmp;

    HASH_ITER(hh, *table, rec, tmp) {
        HASH_DEL(*table, rec);
        free((char *)rec->host);
        free(rec);
    }
}

static void get_stamp(const char *path, struct stamp *stamp) {
    WIN32_FILE_ATTRIBUTE_DATA data;

    memset(stamp, 0, sizeof(*stamp));
    if (GetFileAttributesEx(path, GetFileExInfoStandard, &data)) {
        stamp->time = data.ftLastWriteTime;
        stamp->size = data.nFileSizeLow;
    }
}

static int read_list(const char *filename, const char *verb) {
    char *line = malloc(HOST_MAXLEN + 1);
    size_t linelen = HOST_MAXLEN + 1;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r");
    if (!fp) return FALSE;

    while ((read = getline(&line, &linelen, fp)) != -1) {
        /* works with both \n and \r\n */
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n",
                line);
            continue;
        }
        if (strlen(line) < 2) {
            printf("WARNING: host %s is less than 2 characters, skipping\n", line);
            continue;
        }
        if (add_hostname(line))
            cnt++;
    }
    free(line);
    fclose(fp);
    if (!blackwhitelist) return FALSE;
    printf("%s %d hosts from file %s\n", verb, cnt, filename);
    return TRUE;
}

int blackwhitelist_load_list(const char *filename) {
    if (!read_list(filename, "Loaded"))
        return FALSE;
    if (list_count < MAX_LISTS) {
        if (!GetFullPathName(filename, MAX_PATH, lists[list_count].path, NULL))
            snprintf(lists[list_count].path, MAX_PATH, "%s", filename);
        get_stamp(lists[list_count].path, &lists[list_count].stamp);
        list_count++;
    }
    return TRUE;
}

/* Builds the table again from all files. The old table stays if any of them can't be read. */
static void reload_lists(void) {
    blackwhitelist_record_t *old = blackwhitelist;
    int i, ok = TRUE;

    blackwhitelist = NULL;
    for (i = 0; i < list_count && ok; i++)
        ok = read_list(lists[i].path, "Reloaded");
    if (ok) {
        free_table(&old);
        return;
    }
    free_table(&blackwhitelist);
    blackwhitelist = old;
    printf("WARNING: can't read the blacklist again, keeping the previous one\n");
}

/* Looks at the files now and then; at most one look per RELOAD_INTERVAL_MS. */
static void reload_if_changed(void) {
    ULONGLONG now = GetTickCount64();
    int i, changed = FALSE;

    if (now < next_check)
        return;
    next_check = now + RELOAD_INTERVAL_MS;
    for (i = 0; i < list_count; i++) {
        struct stamp stamp;

        get_stamp(lists[i].path, &stamp);
        if (CompareFileTime(&stamp.time, &lists[i].stamp.time) != 0 || stamp.size != lists[i].stamp.size) {
            lists[i].stamp = stamp;     /* a broken file is tried again only after it changes again */
            changed = TRUE;
        }
    }
    if (changed)
        reload_lists();
}

int blackwhitelist_check_hostname(const char *host_addr, size_t host_len) {
    char current_host[HOST_MAXLEN + 1];
    char *tokenized_host = NULL;

    if (host_len > HOST_MAXLEN) return FALSE;
    reload_if_changed();
    if (host_addr && host_len) {
        memcpy(current_host, host_addr, host_len);
        current_host[host_len] = '\0';
    }

    if (check_get_hostname(current_host))
            return TRUE;

    tokenized_host = strchr(current_host, '.');
    while (tokenized_host != NULL && tokenized_host < (current_host + HOST_MAXLEN)) {
        if (check_get_hostname(tokenized_host + 1))
            return TRUE;
        tokenized_host = strchr(tokenized_host + 1, '.');
    }

    debug("____blackwhitelist_check_hostname FALSE: host %s\n", current_host);
    return FALSE;
}
