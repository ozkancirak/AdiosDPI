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

typedef struct domain_record {
    const char *host;
    UT_hash_handle hh;   /* makes this structure hashable */
} domain_record_t;

#define MAX_LISTS 16
#define RELOAD_INTERVAL_MS 3000

/* What a file looked like when it was read. The size also catches an edit within the same clock tick. */
struct stamp {
    FILETIME time;
    DWORD size;
};

struct domain_list {
    domain_record_t *table;
    /* The files the table was built from (more than MAX_LISTS are loaded but not watched). */
    struct {
        char path[MAX_PATH];
        struct stamp stamp;
    } files[MAX_LISTS];
    int file_count;
    ULONGLONG next_check;
};

/* --blacklist says what to trick, --blacklist-exclude says what to leave alone. */
static struct domain_list blacklist;
static struct domain_list exclusions;

static int check_get_hostname(struct domain_list *list, const char *host) {
    domain_record_t *tmp_record = NULL;
    if (!list->table) return FALSE;

    HASH_FIND_STR(list->table, host, tmp_record);
    if (tmp_record) {
        debug("check_get_hostname found host\n");
        return TRUE;
    }
    debug("check_get_hostname host not found\n");
    return FALSE;
}

static int add_hostname(struct domain_list *list, const char *host) {
    domain_record_t *tmp_record;
    char *host_c;

    if (!host)
        return FALSE;
    if (check_get_hostname(list, host)) {
        debug("Not added host %s\n", host);
        return FALSE;
    }
    tmp_record = malloc(sizeof(domain_record_t));
    host_c = strdup(host);
    if (!tmp_record || !host_c) {
        free(tmp_record);
        free(host_c);
        return FALSE;
    }
    tmp_record->host = host_c;
    HASH_ADD_KEYPTR(hh, list->table, tmp_record->host,
                    strlen(tmp_record->host), tmp_record);
    debug("Added host %s\n", host_c);
    return TRUE;
}

/* Host names are not case sensitive, so the table and the names to look up are all lowercase. */
static void to_lower(char *s) {
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s + ('a' - 'A'));
}

static void free_table(domain_record_t **table) {
    domain_record_t *rec, *tmp;

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

static int read_list(struct domain_list *list, const char *filename, const char *verb) {
    char *line;
    size_t linelen = HOST_MAXLEN + 1;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r");
    if (!fp) return FALSE;
    line = malloc(linelen);
    if (!line) {
        fclose(fp);
        return FALSE;
    }

    while ((read = getline(&line, &linelen, fp)) != -1) {
        /* works with both \n and \r\n */
        line[strcspn(line, "\r\n")] = '\0';
        to_lower(line);
        if (strlen(line) > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n",
                line);
            continue;
        }
        if (strlen(line) < 2) {
            printf("WARNING: host %s is less than 2 characters, skipping\n", line);
            continue;
        }
        if (add_hostname(list, line))
            cnt++;
    }
    free(line);
    fclose(fp);
    if (!list->table) return FALSE;
    printf("%s %d hosts from file %s\n", verb, cnt, filename);
    return TRUE;
}

static int load_list(struct domain_list *list, const char *filename) {
    if (!read_list(list, filename, "Loaded"))
        return FALSE;
    if (list->file_count < MAX_LISTS) {
        if (!GetFullPathName(filename, MAX_PATH, list->files[list->file_count].path, NULL))
            snprintf(list->files[list->file_count].path, MAX_PATH, "%s", filename);
        get_stamp(list->files[list->file_count].path, &list->files[list->file_count].stamp);
        list->file_count++;
    }
    return TRUE;
}

/* Builds the table again from all files. The old table stays if any of them can't be read. */
static void reload_lists(struct domain_list *list) {
    domain_record_t *old = list->table;
    int i, ok = TRUE;

    list->table = NULL;
    for (i = 0; i < list->file_count && ok; i++)
        ok = read_list(list, list->files[i].path, "Reloaded");
    if (ok) {
        free_table(&old);
        return;
    }
    free_table(&list->table);
    list->table = old;
    printf("WARNING: can't read the lists again, keeping the previous ones\n");
}

/* Looks at the files now and then; at most one look per RELOAD_INTERVAL_MS. */
static void reload_if_changed(struct domain_list *list) {
    ULONGLONG now = GetTickCount64();
    int i, changed = FALSE;

    if (now < list->next_check)
        return;
    list->next_check = now + RELOAD_INTERVAL_MS;
    for (i = 0; i < list->file_count; i++) {
        struct stamp stamp;

        get_stamp(list->files[i].path, &stamp);
        if (CompareFileTime(&stamp.time, &list->files[i].stamp.time) != 0 ||
            stamp.size != list->files[i].stamp.size) {
            list->files[i].stamp = stamp;   /* a broken file is tried again only after it changes again */
            changed = TRUE;
        }
    }
    if (changed)
        reload_lists(list);
}

int blackwhitelist_load_list(const char *filename) {
    return load_list(&blacklist, filename);
}

int blackwhitelist_load_exclude_list(const char *filename) {
    return load_list(&exclusions, filename);
}

int blackwhitelist_have_exclusions(void) {
    return exclusions.table != NULL;
}

/* True for the host itself and for any name below it (example.com matches www.example.com). */
static int contains_hostname(struct domain_list *list, const char *host) {
    const char *tokenized_host;

    if (check_get_hostname(list, host))
        return TRUE;

    tokenized_host = strchr(host, '.');
    while (tokenized_host != NULL && tokenized_host < (host + HOST_MAXLEN)) {
        if (check_get_hostname(list, tokenized_host + 1))
            return TRUE;
        tokenized_host = strchr(tokenized_host + 1, '.');
    }
    return FALSE;
}

int blackwhitelist_check_hostname(const char *host_addr, size_t host_len) {
    char current_host[HOST_MAXLEN + 1];

    if (host_len > HOST_MAXLEN) return FALSE;
    current_host[0] = '\0';             /* an empty name is looked up as such, not as what the stack held */
    if (host_addr && host_len) {
        memcpy(current_host, host_addr, host_len);
        current_host[host_len] = '\0';
        to_lower(current_host);
    }
    reload_if_changed(&blacklist);
    reload_if_changed(&exclusions);

    if (contains_hostname(&exclusions, current_host)) {
        debug("____blackwhitelist_check_hostname excluded: host %s\n", current_host);
        return FALSE;
    }
    if (contains_hostname(&blacklist, current_host))
        return TRUE;

    debug("____blackwhitelist_check_hostname FALSE: host %s\n", current_host);
    return FALSE;
}
