#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>

#include "crypto.h"

#define DEFAULT_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096
#define DEFAULT_MAX_USERNAME 10
#define DEFAULT_MAX_PASSWORD 64
#define MAX_MSG_LEN 512
#define MAX_KEY_LEN 128

#define USERS_FILE "users.txt"
#define HISTORY_FILE "history.txt"
#define CONFIG_FILE "host.conf"
#define BANNED_FILE "banned.txt"
#define HISTORY_CONFIG_FILE "history.conf"
#define DELAY_CONFIG_FILE "delay.conf"
#define KEY_CONFIG_FILE "key.conf"
#define ANTISPAM_CONFIG_FILE "antispam.conf"
#define FILESIZE_CONFIG_FILE "filesize.conf"
#define LIMITS_CONFIG_FILE "limits.conf"

#define FILE_DIR "files"
#define FILE_INDEX "files.index"
#define FILE_CHUNK_SIZE 2048
#define DEFAULT_MAX_FILE_SIZE (16LL * 1024 * 1024)
#define MAX_FILE_NAME 200
#define MAX_B64_NAME 512

/* history.conf: number of history entries to keep (0 = unlimited).
   When an entry that announces a file is trimmed, that file is deleted.
   filesize.conf: upload limit in kb/mb/gb/tb (values are added together).
   delay.conf: global delay in seconds for all users (0 = disabled).
   antispam.conf: repeat count limit for spam ban (0 = disabled). */
#define MAX_DELAY_SECONDS 86400

static long long max_file_size = DEFAULT_MAX_FILE_SIZE;
static size_t max_username_len = DEFAULT_MAX_USERNAME;
static size_t max_password_len = DEFAULT_MAX_PASSWORD;
static char *client_usernames[MAX_CLIENTS];

static void delete_file_from_history_line(const char *line);

int load_or_create_config() {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        f = fopen(CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "%d\n", DEFAULT_PORT);
            fclose(f);
        }
        printf("Created config file %s with default port: %d\n", CONFIG_FILE, DEFAULT_PORT);
        return DEFAULT_PORT;
    }
    int port = DEFAULT_PORT;
    if (fscanf(f, "%d", &port) != 1) {
        port = DEFAULT_PORT;
    }
    fclose(f);
    return port;
}

static void load_or_create_key(char *key_buf, size_t max_len) {
    FILE *f = fopen(KEY_CONFIG_FILE, "r");
    if (!f) {
        f = fopen(KEY_CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "YourKey\n");
            fclose(f);
        }
        snprintf(key_buf, max_len, "YourKey");
        printf("Created config file %s with default key: YourKey\n", KEY_CONFIG_FILE);
        return;
    }

    if (fgets(key_buf, max_len, f) != NULL) {
        key_buf[strcspn(key_buf, "\r\n")] = '\0';
    } else {
        snprintf(key_buf, max_len, "YourKey");
    }
    fclose(f);
}

static long long load_nonnegative_config(const char *path, long long default_value) {
    FILE *f = fopen(path, "r");
    if (!f) {
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "%lld\n", default_value);
            fclose(f);
            printf("Created config file %s with default value: %lld\n", path, default_value);
        }
        return default_value;
    }

    long long value = default_value;
    if (fscanf(f, "%lld", &value) != 1 || value < 0) {
        printf("Invalid value in %s, using default: %lld\n", path, default_value);
        value = default_value;
    }
    fclose(f);
    return value;
}

static char *trim_config_token(char *text) {
    while (*text == ' ' || *text == '\t') text++;

    char *end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static long long units_to_file_size(long long kb, long long mb,
                                    long long gb, long long tb) {
    const long long values[4] = {kb, mb, gb, tb};
    const unsigned long long multipliers[4] = {
        1024ULL,
        1024ULL * 1024ULL,
        1024ULL * 1024ULL * 1024ULL,
        1024ULL * 1024ULL * 1024ULL * 1024ULL
    };

    unsigned long long total = 0;
    for (int i = 0; i < 4; i++) {
        unsigned long long value = (unsigned long long)values[i];
        if (value > (ULLONG_MAX - total) / multipliers[i]) {
            return LLONG_MAX;
        }
        total += value * multipliers[i];
    }

    if (total > (unsigned long long)LLONG_MAX) {
        return LLONG_MAX;
    }
    return (long long)total;
}

/* filesize.conf contains four values that are added together:
       kb = 0
       mb = 16
       gb = 0
       tb = 0
   With the defaults above the upload limit is 16 MiB. */
static long long load_file_size_config(void) {
    FILE *f = fopen(FILESIZE_CONFIG_FILE, "r");
    if (!f) {
        f = fopen(FILESIZE_CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "kb = 0\nmb = 16\ngb = 0\ntb = 0\n");
            fclose(f);
            printf("Created config file %s with default size: 16 MB\n",
                   FILESIZE_CONFIG_FILE);
        }
        return DEFAULT_MAX_FILE_SIZE;
    }

    long long values[4] = {0, 0, 0, 0};
    int recognized = 0;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        char *entry = trim_config_token(line);
        if (*entry == '\0' || *entry == '#') continue;

        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            printf("Ignoring invalid line in %s: %s\n",
                   FILESIZE_CONFIG_FILE, entry);
            continue;
        }

        *equals = '\0';
        char *key = trim_config_token(entry);
        char *value_text = trim_config_token(equals + 1);

        char *comment = strchr(value_text, '#');
        if (comment != NULL) {
            *comment = '\0';
            value_text = trim_config_token(value_text);
        }

        if (*key == '\0' || *value_text == '\0') continue;

        for (char *p = key; *p; p++) {
            *p = (char)tolower((unsigned char)*p);
        }

        char *end = NULL;
        errno = 0;
        long long value = strtoll(value_text, &end, 10);
        if (errno != 0 || end == value_text || *end != '\0' || value < 0) {
            printf("Invalid value for %s in %s: %s\n",
                   key, FILESIZE_CONFIG_FILE, value_text);
            continue;
        }

        int index = -1;
        if (strcmp(key, "kb") == 0) index = 0;
        else if (strcmp(key, "mb") == 0) index = 1;
        else if (strcmp(key, "gb") == 0) index = 2;
        else if (strcmp(key, "tb") == 0) index = 3;

        if (index < 0) {
            printf("Unknown key in %s: %s\n", FILESIZE_CONFIG_FILE, key);
            continue;
        }

        values[index] = value;
        recognized = 1;
    }
    fclose(f);

    if (!recognized) {
        printf("No valid entries in %s, using default size: %lld bytes\n",
               FILESIZE_CONFIG_FILE, DEFAULT_MAX_FILE_SIZE);
        return DEFAULT_MAX_FILE_SIZE;
    }

    return units_to_file_size(values[0], values[1], values[2], values[3]);
}

/* limits.conf controls how long usernames and passwords may be.  The client
   receives these values before it asks for credentials, so the prompts and
   validation follow the server configuration instead of hard-coded client
   limits. */
static void load_limits_config(void) {
    FILE *f = fopen(LIMITS_CONFIG_FILE, "r");
    if (!f) {
        f = fopen(LIMITS_CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "# Maximum username and password length accepted by the server.\n"
                       "max_username = %d\nmax_password = %d\n",
                    DEFAULT_MAX_USERNAME, DEFAULT_MAX_PASSWORD);
            fclose(f);
            printf("Created config file %s with defaults: username %d, password %d\n",
                   LIMITS_CONFIG_FILE, DEFAULT_MAX_USERNAME, DEFAULT_MAX_PASSWORD);
        }
        return;
    }

    int username_set = 0;
    int password_set = 0;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        char *entry = trim_config_token(line);
        if (*entry == '\0' || *entry == '#') continue;

        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            printf("Ignoring invalid line in %s: %s\n", LIMITS_CONFIG_FILE, entry);
            continue;
        }

        *equals = '\0';
        char *key = trim_config_token(entry);
        char *value_text = trim_config_token(equals + 1);

        char *comment = strchr(value_text, '#');
        if (comment != NULL) {
            *comment = '\0';
            value_text = trim_config_token(value_text);
        }
        if (*key == '\0' || *value_text == '\0') continue;

        for (char *p = key; *p; p++) {
            *p = (char)tolower((unsigned char)*p);
        }

        char *end = NULL;
        errno = 0;
        long long value = strtoll(value_text, &end, 10);
        if (errno != 0 || end == value_text || *end != '\0' || value < 1) {
            printf("Invalid value for %s in %s: %s\n",
                   key, LIMITS_CONFIG_FILE, value_text);
            continue;
        }

        if (strcmp(key, "max_username") == 0 ||
            strcmp(key, "max_nickname") == 0) {
            if ((unsigned long long)value > (unsigned long long)SIZE_MAX) {
                printf("max_username in %s is too large for this platform, ignoring.\n",
                       LIMITS_CONFIG_FILE);
                continue;
            }
            max_username_len = (size_t)value;
            username_set = 1;
        } else if (strcmp(key, "max_password") == 0) {
            if ((unsigned long long)value > (unsigned long long)SIZE_MAX) {
                printf("max_password in %s is too large for this platform, ignoring.\n",
                       LIMITS_CONFIG_FILE);
                continue;
            }
            max_password_len = (size_t)value;
            password_set = 1;
        } else {
            printf("Unknown key in %s: %s\n", LIMITS_CONFIG_FILE, key);
        }
    }
    fclose(f);

    if (!username_set) max_username_len = DEFAULT_MAX_USERNAME;
    if (!password_set) max_password_len = DEFAULT_MAX_PASSWORD;
}

unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static long long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Builds a chat line with the server's local date and time.  The timestamp is
   added when the server accepts the message, so everyone (including the
   sender) sees the same server time and history keeps it as well.  The result
   is allocated with malloc() and must be freed by the caller. */
static char *make_timestamped(const char *fmt, ...) {
    char stamp[32];

    time_t now = time(NULL);
    struct tm local_now;
    if (localtime_r(&now, &local_now) == NULL) {
        snprintf(stamp, sizeof(stamp), "0000-00-00 00:00:00");
    } else {
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local_now);
    }

    va_list ap;
    va_list ap_copy;
    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    int body_len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (body_len < 0) {
        va_end(ap_copy);
        return NULL;
    }

    char *body = malloc((size_t)body_len + 1);
    if (body == NULL) {
        va_end(ap_copy);
        return NULL;
    }
    vsnprintf(body, (size_t)body_len + 1, fmt, ap_copy);
    va_end(ap_copy);

    size_t total = strlen(stamp) + 3 + strlen(body) + 1;
    char *out = malloc(total);
    if (out != NULL) {
        snprintf(out, total, "[%s] %s", stamp, body);
    }

    free(body);
    return out;
}

static int is_banned(const char *username) {
    FILE *f = fopen(BANNED_FILE, "r");
    if (!f) return 0;

    char *line = NULL;
    size_t cap = 0;
    int found = 0;

    while (getline(&line, &cap, f) >= 0) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, username) == 0) {
            found = 1;
            break;
        }
    }

    free(line);
    fclose(f);
    return found;
}

static void ban_username(const char *username) {
    if (is_banned(username)) return;

    FILE *f = fopen(BANNED_FILE, "a");
    if (f) {
        fprintf(f, "%s\n", username);
        fclose(f);
    }
}

int handle_auth(int client_sock, char *out_username, size_t out_cap) {
    int result = 0;
    int action = 0;
    char *auth_data = NULL;
    char *f_user = NULL;
    size_t auth_len = 0;

    if (max_username_len > SIZE_MAX - sizeof(int) - 2 ||
        max_password_len > SIZE_MAX - sizeof(int) - max_username_len - 2) {
        return 0;
    }

    size_t auth_cap = sizeof(int) + max_username_len + 1 +
                      max_password_len + 1;
    auth_data = malloc(auth_cap);
    f_user = malloc(max_username_len + 1);
    if (auth_data == NULL || f_user == NULL) goto done;

    memset(auth_data, 0, auth_cap);

    if (cchat_recv_encrypted(client_sock, auth_data, auth_cap, &auth_len) != 1) {
        goto done;
    }
    if (auth_len < sizeof(int) + 2) goto done;

    memcpy(&action, auth_data, sizeof(int));
    if (action != 1 && action != 2) goto done;

    const char *user_text = auth_data + sizeof(int);
    size_t remain = auth_len - sizeof(int);
    const char *user_end = memchr(user_text, '\0', remain);
    if (user_end == NULL) goto done;

    size_t user_len = (size_t)(user_end - user_text);
    const char *pass_text = user_end + 1;
    size_t pass_remain = auth_len - (size_t)(pass_text - auth_data);
    const char *pass_end = memchr(pass_text, '\0', pass_remain);
    if (pass_end == NULL) goto done;

    size_t pass_len = (size_t)(pass_end - pass_text);
    if (user_len == 0 || user_len > max_username_len) {
        char *msg = "ERR_USERNAME_TOO_LONG";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        goto done;
    }
    if (pass_len > max_password_len) {
        char *msg = "ERR_PASSWORD_TOO_LONG";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        goto done;
    }

    char *username = (char *)user_text;
    char *password = (char *)pass_text;

    if (is_banned(username)) {
        char *msg = "ERR_BANNED";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        goto done;
    }

    unsigned long p_hash = hash_password(password);

    char user_fmt[64];
    snprintf(user_fmt, sizeof(user_fmt), "%%%zus %%lu", max_username_len);

    FILE *f = fopen(USERS_FILE, "r");
    int user_exists = 0;

    if (f) {
        unsigned long f_hash;
        while (fscanf(f, user_fmt, f_user, &f_hash) == 2) {
            if (strcmp(f_user, username) == 0) {
                user_exists = 1;
                break;
            }
        }
        fclose(f);
    }

    if (action == 2) {
        if (user_exists) {
            char *msg = "ERR_USER_EXISTS";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            goto done;
        }

        f = fopen(USERS_FILE, "a");
        if (!f) {
            char *msg = "ERR_SERVER";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            goto done;
        }
        fprintf(f, "%s %lu\n", username, p_hash);
        fclose(f);

        char *msg = "OK";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        snprintf(out_username, out_cap, "%s", username);
        result = 1;
        goto done;
    }

    if (!user_exists) {
        char *msg = "ERR_INVALID_CREDENTIALS";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        goto done;
    }

    f = fopen(USERS_FILE, "r");
    if (!f) goto done;

    unsigned long f_hash;
    int authenticated = 0;
    while (fscanf(f, user_fmt, f_user, &f_hash) == 2) {
        if (strcmp(f_user, username) == 0 && f_hash == p_hash) {
            authenticated = 1;
            break;
        }
    }
    fclose(f);

    if (authenticated) {
        char *msg = "OK";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        snprintf(out_username, out_cap, "%s", username);
        result = 1;
    } else {
        char *msg = "ERR_INVALID_CREDENTIALS";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
    }

done:
    free(auth_data);
    free(f_user);
    return result;
}

void send_history(int client_sock) {
    FILE *f = fopen(HISTORY_FILE, "r");
    if (!f) return;

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), f)) {
        cchat_send_encrypted(client_sock, line, strlen(line));
    }
    fclose(f);
}

static void trim_history(long long limit) {
    if (limit <= 0) return;

    FILE *f = fopen(HISTORY_FILE, "r");
    if (!f) return;

    long long line_count = 0;
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), f)) {
        line_count++;
    }

    if (line_count <= limit) {
        fclose(f);
        return;
    }

    long long skip = line_count - limit;
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return;
    }

    FILE *tmp = fopen(HISTORY_FILE ".tmp", "w");
    if (!tmp) {
        fclose(f);
        return;
    }

    for (long long i = 0; i < skip; i++) {
        if (!fgets(line, sizeof(line), f)) break;
        delete_file_from_history_line(line);
    }
    while (fgets(line, sizeof(line), f)) {
        fputs(line, tmp);
    }

    fclose(tmp);
    fclose(f);

    if (rename(HISTORY_FILE ".tmp", HISTORY_FILE) != 0) {
        remove(HISTORY_FILE ".tmp");
    }
}

void save_to_history(const char *msg, long long limit) {
    FILE *f = fopen(HISTORY_FILE, "a");
    if (f) {
        fprintf(f, "%s", msg);
        fclose(f);
        trim_history(limit);
    }
}

/* --------------------------- File transfers --------------------------- */

typedef struct {
    int active;
    FILE *fp;
    long long id;
    long long size;
    long long received;
    char name[MAX_FILE_NAME + 1];
    char name_b64[MAX_B64_NAME];
} upload_state;

static upload_state uploads[MAX_CLIENTS];
static long long next_file_id = 1;

static void ensure_file_dir(void) {
    if (mkdir(FILE_DIR, 0755) != 0 && errno != EEXIST) {
        printf("Warning: cannot create %s: %s\n", FILE_DIR, strerror(errno));
    }
}

static void build_index_format(char *out, size_t cap) {
    snprintf(out, cap, "%%lld %%lld %%%zus %%511s", max_username_len);
}

static void load_next_file_id(void) {
    next_file_id = 1;

    FILE *f = fopen(FILE_INDEX, "r");
    if (!f) return;

    char user_fmt[64];
    build_index_format(user_fmt, sizeof(user_fmt));
    char *user = malloc(max_username_len + 1);
    if (user == NULL) {
        fclose(f);
        return;
    }

    long long id, size;
    char b64[MAX_B64_NAME];
    while (fscanf(f, user_fmt, &id, &size, user, b64) == 4) {
        if (id >= next_file_id) next_file_id = id + 1;
    }
    free(user);
    fclose(f);
}

static void sanitize_file_name(char *name) {
    for (char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c == 127) *p = '_';
    }
}

static int index_lookup(long long id, long long *size, char *name_b64,
                        size_t name_cap) {
    FILE *f = fopen(FILE_INDEX, "r");
    if (!f) return 0;

    char user_fmt[64];
    build_index_format(user_fmt, sizeof(user_fmt));
    char *user = malloc(max_username_len + 1);
    if (user == NULL) {
        fclose(f);
        return 0;
    }

    long long fid, fsize;
    char b64[MAX_B64_NAME];
    int found = 0;

    while (fscanf(f, user_fmt, &fid, &fsize, user, b64) == 4) {
        if (fid == id) {
            if (size) *size = fsize;
            if (name_b64) snprintf(name_b64, name_cap, "%s", b64);
            found = 1;
            break;
        }
    }
    free(user);
    fclose(f);
    return found;
}

static void remove_file_index_entry(long long id) {
    FILE *f = fopen(FILE_INDEX, "r");
    if (f == NULL) return;

    FILE *tmp = fopen(FILE_INDEX ".tmp", "w");
    if (tmp == NULL) {
        printf("Warning: cannot rewrite %s: %s\n",
               FILE_INDEX, strerror(errno));
        fclose(f);
        return;
    }

    char line[BUFFER_SIZE];
    int removed = 0;

    while (fgets(line, sizeof(line), f)) {
        long long file_id = 0;
        if (sscanf(line, "%lld", &file_id) == 1 && file_id == id) {
            removed = 1;
            continue;
        }
        fputs(line, tmp);
    }

    fclose(f);
    fclose(tmp);

    if (!removed) {
        remove(FILE_INDEX ".tmp");
        return;
    }

    if (rename(FILE_INDEX ".tmp", FILE_INDEX) != 0) {
        printf("Warning: cannot update %s: %s\n",
               FILE_INDEX, strerror(errno));
        remove(FILE_INDEX ".tmp");
    }
}

/* Called for history lines that are about to leave the history file.  If the
   line announces an uploaded file, the stored file and its index entry are
   removed as well. */
static void delete_file_from_history_line(const char *line) {
    /* Newer history lines start with "[YYYY-MM-DD HH:MM:SS] ".  Older ones
       do not, so accept both forms but still require a real server line. */
    const char *server_part = line;
    if (strlen(line) >= 22 && line[0] == '[' && line[20] == ']' &&
        line[21] == ' ' && line[5] == '-' && line[8] == '-' &&
        line[11] == ' ' && line[14] == ':' && line[17] == ':') {
        server_part = line + 22;
    }

    if (strncmp(server_part, "[Server]: User ", 15) != 0) return;

    const char *marker = strstr(server_part, " uploaded file #");
    if (marker == NULL) return;

    const char *number = marker + strlen(" uploaded file #");
    char *end = NULL;
    errno = 0;
    long long id = strtoll(number, &end, 10);
    if (errno != 0 || end == number || id <= 0) return;
    if (*end != ' ' && *end != '\r' && *end != '\n' && *end != '\0') return;

    char path[256];
    snprintf(path, sizeof(path), "%s/%lld", FILE_DIR, id);

    if (remove(path) != 0 && errno != ENOENT) {
        printf("Warning: cannot delete file %s: %s\n",
               path, strerror(errno));
        return;
    }

    remove_file_index_entry(id);
    printf("Deleted file #%lld because its history entry was trimmed.\n", id);
}

static void upload_close_file(upload_state *up, int remove_part) {
    if (up->fp) {
        fclose(up->fp);
        up->fp = NULL;
    }
    if (remove_part) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%lld.part", FILE_DIR, up->id);
        remove(path);
    }
    up->active = 0;
}

static void upload_abort(upload_state *up, int sd, const char *reason) {
    upload_close_file(up, 1);
    if (sd >= 0) {
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "@UPLOAD_ERR %s\n", reason);
        cchat_send_encrypted(sd, msg, strlen(msg));
    }
}

static void handle_upload_begin(upload_state *up, int sd, const char *frame) {
    long long size;
    char b64[MAX_B64_NAME];

    if (sscanf(frame + 14, "%lld %511s", &size, b64) != 2) {
        upload_abort(up, sd, "invalid headers");
        return;
    }

    if (size < 0 || size > max_file_size) {
        upload_abort(up, sd, "file exceeds the configured size limit");
        return;
    }

    if (up->active) {
        upload_abort(up, sd, "previous upload cancelled");
    }

    uint8_t decoded[MAX_FILE_NAME + 1];
    size_t decoded_len = 0;
    if (cchat_b64_decode(b64, strlen(b64), decoded,
                         sizeof(decoded) - 1, &decoded_len) != 0 ||
        decoded_len == 0) {
        upload_abort(up, sd, "invalid file name");
        return;
    }
    decoded[decoded_len] = '\0';

    long long id = next_file_id++;
    char path[256];
    snprintf(path, sizeof(path), "%s/%lld.part", FILE_DIR, id);

    FILE *f = fopen(path, "wb");
    if (!f) {
        upload_abort(up, sd, "server cannot create file");
        return;
    }

    up->active = 1;
    up->fp = f;
    up->id = id;
    up->size = size;
    up->received = 0;
    memcpy(up->name, decoded, decoded_len + 1);
    up->name[MAX_FILE_NAME] = '\0';
    sanitize_file_name(up->name);
    snprintf(up->name_b64, sizeof(up->name_b64), "%s", b64);
}

static void handle_upload_data(upload_state *up, int sd, const char *frame) {
    if (!up->active) return;

    uint8_t data[FILE_CHUNK_SIZE + 4];
    size_t data_len = 0;
    if (cchat_b64_decode(frame + 13, strlen(frame + 13), data,
                         sizeof(data), &data_len) != 0) {
        upload_abort(up, sd, "corrupted upload data");
        return;
    }

    if (up->received + (long long)data_len > up->size) {
        upload_abort(up, sd, "upload exceeds announced size");
        return;
    }

    if (data_len > 0 && fwrite(data, 1, data_len, up->fp) != data_len) {
        upload_abort(up, sd, "server write error");
        return;
    }
    up->received += (long long)data_len;
}

static void broadcast_to_all(int client_sockets[MAX_CLIENTS],
                             const char *msg) {
    for (int j = 0; j < MAX_CLIENTS; j++) {
        int cs = client_sockets[j];
        if (cs != 0) {
            cchat_send_encrypted(cs, msg, strlen(msg));
        }
    }
}

static void handle_upload_end(upload_state *up, int sd, const char *username,
                              long long history_limit,
                              int client_sockets[MAX_CLIENTS]) {
    if (!up->active) return;

    if (up->received != up->size) {
        upload_abort(up, sd, "incomplete upload");
        return;
    }

    fflush(up->fp);
    fclose(up->fp);
    up->fp = NULL;

    char part_path[256];
    char final_path[256];
    snprintf(part_path, sizeof(part_path), "%s/%lld.part", FILE_DIR, up->id);
    snprintf(final_path, sizeof(final_path), "%s/%lld", FILE_DIR, up->id);

    if (rename(part_path, final_path) != 0) {
        upload_abort(up, sd, "server cannot store file");
        return;
    }

    FILE *idx = fopen(FILE_INDEX, "a");
    if (!idx) {
        remove(final_path);
        upload_abort(up, sd, "server cannot update file index");
        return;
    }
    fprintf(idx, "%lld %lld %s %s\n", up->id, up->size, username,
            up->name_b64);
    fclose(idx);

    char *announce = make_timestamped(
        "[Server]: User %s uploaded file #%lld \"%s\" (%lld bytes).\n",
        username, up->id, up->name, up->size);
    if (announce != NULL) {
        save_to_history(announce, history_limit);
        broadcast_to_all(client_sockets, announce);
        free(announce);
    }

    up->active = 0;
}

static void handle_file_list(int sd) {
    FILE *f = fopen(FILE_INDEX, "r");
    if (f) {
        char user_fmt[64];
        build_index_format(user_fmt, sizeof(user_fmt));

        char *user = malloc(max_username_len + 1);
        size_t line_cap = max_username_len + MAX_B64_NAME + 128;
        char *line = malloc(line_cap);
        if (user == NULL || line == NULL) {
            free(user);
            free(line);
            fclose(f);
            const char *end = "@FILE_LIST_END\n";
            cchat_send_encrypted(sd, end, strlen(end));
            return;
        }

        long long id, size;
        char b64[MAX_B64_NAME];

        while (fscanf(f, user_fmt, &id, &size, user, b64) == 4) {
            snprintf(line, line_cap, "@FILE_ENTRY %lld %lld %s %s\n",
                     id, size, user, b64);
            if (cchat_send_encrypted(sd, line, strlen(line)) <= 0) {
                free(user);
                free(line);
                fclose(f);
                return;
            }
        }
        free(user);
        free(line);
        fclose(f);
    }

    const char *end = "@FILE_LIST_END\n";
    cchat_send_encrypted(sd, end, strlen(end));
}

static void handle_file_get(int sd, long long id) {
    long long size = 0;
    char b64[MAX_B64_NAME];

    if (id <= 0 || !index_lookup(id, &size, b64, sizeof(b64))) {
        char msg[128];
        snprintf(msg, sizeof(msg), "@FILE_ERR %lld not found\n", id);
        cchat_send_encrypted(sd, msg, strlen(msg));
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/%lld", FILE_DIR, id);
    FILE *f = fopen(path, "rb");
    if (!f) {
        char msg[128];
        snprintf(msg, sizeof(msg), "@FILE_ERR %lld missing on server\n", id);
        cchat_send_encrypted(sd, msg, strlen(msg));
        return;
    }

    char line[BUFFER_SIZE];
    snprintf(line, sizeof(line), "@FILE_BEGIN %lld %lld %s\n", id, size, b64);
    if (cchat_send_encrypted(sd, line, strlen(line)) <= 0) {
        fclose(f);
        return;
    }

    uint8_t data[FILE_CHUNK_SIZE];
    char encoded[4 * ((FILE_CHUNK_SIZE + 2) / 3) + 1];
    size_t n;
    while ((n = fread(data, 1, sizeof(data), f)) > 0) {
        if (cchat_b64_encode(data, n, encoded, sizeof(encoded)) < 0) break;
        snprintf(line, sizeof(line), "@FILE_DATA %lld %s\n", id, encoded);
        if (cchat_send_encrypted(sd, line, strlen(line)) <= 0) {
            fclose(f);
            return;
        }
    }
    fclose(f);

    snprintf(line, sizeof(line), "@FILE_END %lld\n", id);
    cchat_send_encrypted(sd, line, strlen(line));
}

static int handle_control_frame(int slot, int sd, const char *frame,
                                const char *username, long long history_limit,
                                int client_sockets[MAX_CLIENTS]) {
    upload_state *up = &uploads[slot];

    if (strncmp(frame, "@UPLOAD_BEGIN ", 14) == 0) {
        handle_upload_begin(up, sd, frame);
        return 1;
    }
    if (strncmp(frame, "@UPLOAD_DATA ", 13) == 0) {
        handle_upload_data(up, sd, frame);
        return 1;
    }
    if (strncmp(frame, "@UPLOAD_END", 11) == 0) {
        handle_upload_end(up, sd, username, history_limit, client_sockets);
        return 1;
    }
    if (strncmp(frame, "@FILE_LIST", 10) == 0) {
        handle_file_list(sd);
        return 1;
    }
    if (strncmp(frame, "@FILE_GET ", 10) == 0) {
        handle_file_get(sd, atoll(frame + 10));
        return 1;
    }
    /* Client heartbeat: answer with @PONG.  Neither frame is a chat message,
       so nothing is saved to history or broadcast to other clients. */
    if (strncmp(frame, "@PING", 5) == 0) {
        const char pong_frame[] = "@PONG\n";
        cchat_send_encrypted(sd, pong_frame, sizeof(pong_frame) - 1);
        return 1;
    }
    return 0;
}

int main() {
    char server_key[MAX_KEY_LEN];
    load_or_create_key(server_key, sizeof(server_key));

    if (cchat_set_key(server_key) != 0) {
        fprintf(stderr, "Invalid server encryption key.\n");
        return 1;
    }

    int PORT = load_or_create_config();
    long long history_limit = load_nonnegative_config(HISTORY_CONFIG_FILE, 0);
    long long delay_seconds = load_nonnegative_config(DELAY_CONFIG_FILE, 0);
    long long antispam_limit = load_nonnegative_config(ANTISPAM_CONFIG_FILE, 0);
    max_file_size = load_file_size_config();
    load_limits_config();

    if (delay_seconds > MAX_DELAY_SECONDS) {
        printf("Delay in %s is too large, using %d seconds.\n",
               DELAY_CONFIG_FILE, MAX_DELAY_SECONDS);
        delay_seconds = MAX_DELAY_SECONDS;
    }
    long long rate_limit_ms = delay_seconds * 1000;

    trim_history(history_limit);
    ensure_file_dir();
    load_next_file_id();

    for (int i = 0; i < MAX_CLIENTS; i++) {
        memset(&uploads[i], 0, sizeof(uploads[i]));
    }

    printf("History limit: %lld messages (0 = unlimited)\n", history_limit);
    printf("Max file size: %lld bytes\n", max_file_size);
    printf("Max username length: %zu characters\n", max_username_len);
    printf("Max password length: %zu characters\n", max_password_len);
    printf("Global delay: %lld seconds\n", delay_seconds);
    printf("Antispam repeat limit: %lld (0 = disabled)\n", antispam_limit);

    int server_fd, new_socket, client_sockets[MAX_CLIENTS], max_sd, sd, activity;
    size_t msg_len = 0;
    char client_last_message[MAX_CLIENTS][BUFFER_SIZE];
    long long last_global_message_ms = 0;
    int has_global_message = 0;
    int client_repeat_count[MAX_CLIENTS];
    int addrlen;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE];
    fd_set readfds;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
        client_usernames[i] = calloc(1, max_username_len + 1);
        if (client_usernames[i] == NULL) {
            fprintf(stderr, "Cannot allocate username buffers.\n");
            return 1;
        }
        memset(client_last_message[i], 0, BUFFER_SIZE);
        client_repeat_count[i] = 0;
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    addrlen = sizeof(address);
    printf("Server started on port %d. Waiting for connections...\n", PORT);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            printf("Select error\n");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            char *auth_user = calloc(1, max_username_len + 1);
            if (auth_user == NULL) {
                close(new_socket);
                continue;
            }

            char limits_msg[64];
            snprintf(limits_msg, sizeof(limits_msg), "@LIMITS %zu %zu\n",
                     max_username_len, max_password_len);
            if (cchat_send_encrypted(new_socket, limits_msg,
                                     strlen(limits_msg)) <= 0) {
                free(auth_user);
                close(new_socket);
                continue;
            }

            if (handle_auth(new_socket, auth_user, max_username_len + 1)) {
                printf("Client %s successfully authorized!\n", auth_user);

                char delay_msg[64];
                snprintf(delay_msg, sizeof(delay_msg), "@DELAY %lld\n", rate_limit_ms);
                cchat_send_encrypted(new_socket, delay_msg, strlen(delay_msg));

                char max_size_msg[64];
                snprintf(max_size_msg, sizeof(max_size_msg),
                         "@MAX_FILE_SIZE %lld\n", max_file_size);
                cchat_send_encrypted(new_socket, max_size_msg,
                                     strlen(max_size_msg));

                if (rate_limit_ms > 0 && has_global_message) {
                    long long elapsed = monotonic_ms() - last_global_message_ms;
                    if (elapsed < rate_limit_ms) {
                        char cooldown_msg[64];
                        snprintf(cooldown_msg, sizeof(cooldown_msg),
                                 "@COOLDOWN %lld\n", rate_limit_ms - elapsed);
                        cchat_send_encrypted(new_socket, cooldown_msg, strlen(cooldown_msg));
                    }
                }

                send_history(new_socket);

                char *join_msg = make_timestamped(
                    "[Server]: User %s joined the chat.\n", auth_user);
                if (join_msg != NULL) {
                    save_to_history(join_msg, history_limit);

                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        int cs = client_sockets[j];
                        if (cs != 0) {
                            cchat_send_encrypted(cs, join_msg, strlen(join_msg));
                        }
                    }
                    free(join_msg);
                }

                int added = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_sockets[i] == 0) {
                        client_sockets[i] = new_socket;
                        snprintf(client_usernames[i], max_username_len + 1,
                                 "%s", auth_user);
                        client_last_message[i][0] = '\0';
                        client_repeat_count[i] = 0;
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    printf("Too many clients, rejected.\n");
                    close(new_socket);
                }
            } else {
                printf("Client authorization failed, closing connection.\n");
                close(new_socket);
            }

            free(auth_user);
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];

            if (client_sockets[i] != 0 && FD_ISSET(sd, &readfds)) {
                int msg_rc = cchat_recv_encrypted(sd, buffer, sizeof(buffer) - 1, &msg_len);
                
                if (msg_rc <= 0) {
                    printf("Client %s disconnected.\n", client_usernames[i]);
                    upload_close_file(&uploads[i], 1);
                    
                    char *leave_msg = make_timestamped(
                        "[Server]: User %s left the chat.\n",
                        client_usernames[i]);
                    if (leave_msg != NULL) {
                        save_to_history(leave_msg, history_limit);

                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            int cs = client_sockets[j];
                            if (cs != 0 && cs != sd) {
                                cchat_send_encrypted(cs, leave_msg, strlen(leave_msg));
                            }
                        }
                        free(leave_msg);
                    }

                    close(sd);
                    client_sockets[i] = 0;
                    client_usernames[i][0] = '\0';
                    client_last_message[i][0] = '\0';
                    client_repeat_count[i] = 0;
                } else {
                    buffer[msg_len] = '\0';

                    if (buffer[0] == '@') {
                        handle_control_frame(i, sd, buffer,
                                             client_usernames[i],
                                             history_limit, client_sockets);
                        continue;
                    }

                    if (msg_len > MAX_MSG_LEN) {
                        buffer[MAX_MSG_LEN] = '\0';
                    }

                    /* Official clients prefix messages with "[username]: ".
                       Ignore anything else so clients cannot spoof server
                       control frames such as @COOLDOWN or @DELAY. */
                    if (buffer[0] != '[') {
                        continue;
                    }

                    long long now = monotonic_ms();

                    if (antispam_limit > 0) {
                        if (client_repeat_count[i] > 0 &&
                            strcmp(client_last_message[i], buffer) == 0) {
                            client_repeat_count[i]++;
                        } else {
                            snprintf(client_last_message[i], sizeof(client_last_message[i]), "%s", buffer);
                            client_repeat_count[i] = 1;
                        }

                        if (client_repeat_count[i] >= antispam_limit) {
                            ban_username(client_usernames[i]);
                            upload_close_file(&uploads[i], 1);

                            char *ban_msg = make_timestamped(
                                "[Server]: You have been permanently banned for spamming.\n");
                            if (ban_msg != NULL) {
                                cchat_send_encrypted(sd, ban_msg, strlen(ban_msg));
                                free(ban_msg);
                            }
                            printf("Client %s permanently banned for spamming.\n", client_usernames[i]);

                            char *leave_msg = make_timestamped(
                                "[Server]: User %s left the chat.\n",
                                client_usernames[i]);
                            if (leave_msg != NULL) {
                                save_to_history(leave_msg, history_limit);

                                for (int j = 0; j < MAX_CLIENTS; j++) {
                                    int cs = client_sockets[j];
                                    if (cs != 0 && cs != sd) {
                                        cchat_send_encrypted(cs, leave_msg, strlen(leave_msg));
                                    }
                                }
                                free(leave_msg);
                            }

                            close(sd);
                            client_sockets[i] = 0;
                            client_usernames[i][0] = '\0';
                            client_last_message[i][0] = '\0';
                            client_repeat_count[i] = 0;
                            continue;
                        }
                    }

                    if (rate_limit_ms > 0 && has_global_message &&
                        now - last_global_message_ms < rate_limit_ms) {
                        long long wait_ms = rate_limit_ms - (now - last_global_message_ms);
                        char reject_msg[64];
                        snprintf(reject_msg, sizeof(reject_msg), "@REJECT %lld\n", wait_ms);
                        cchat_send_encrypted(sd, reject_msg, strlen(reject_msg));
                        continue;
                    }
                    last_global_message_ms = now;
                    has_global_message = 1;

                    if (rate_limit_ms > 0) {
                        char cooldown_msg[64];
                        snprintf(cooldown_msg, sizeof(cooldown_msg),
                                 "@COOLDOWN %lld\n", rate_limit_ms);
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            int cs = client_sockets[j];
                            if (cs != 0) {
                                cchat_send_encrypted(cs, cooldown_msg, strlen(cooldown_msg));
                            }
                        }
                    }

                    char *timed_msg = make_timestamped("%s", buffer);
                    if (timed_msg != NULL) {
                        save_to_history(timed_msg, history_limit);

                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            int cs = client_sockets[j];
                            if (cs != 0) {
                                cchat_send_encrypted(cs, timed_msg, strlen(timed_msg));
                            }
                        }
                        free(timed_msg);
                    }
                }
            }
        }
    }
    return 0;
}
