#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <pthread.h>
#include <pwd.h>

#include "crypto.h"

#define BUFFER_SIZE 4096
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512
#define MAX_KEY_PATH 4096
#define MAX_CHAT_LINES 5000
#define MAX_SAVED_SERVERS 256
#define MAX_SERVER_NAME 128
#define MAX_ADDRESS_LEN 128

#define FILE_CHUNK_SIZE 2048
#define DEFAULT_MAX_FILE_SIZE (16LL * 1024 * 1024)
#define MAX_B64_NAME 512
#define MAX_REMOTE_FILES 2000
#define MAX_DOWNLOADS 8
#define MAX_SELECTED_FILES 256

typedef struct {
    long long id;
    long long size;
    char uploader[MAX_USER_LEN];
    char name[256];
} remote_file_info;

typedef struct {
    int active;
    long long id;
    FILE *fp;
    char path[MAX_KEY_PATH];
    char name[256];
    long long size;
    long long received;
} download_slot;

typedef struct {
    char name[256];
    int is_dir;
} fm_entry;

typedef struct {
    char *text;
} chat_line;

static volatile sig_atomic_t is_running = 1;
char current_username[MAX_USER_LEN];

static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static char input_line[BUFFER_SIZE];
static size_t input_line_len = 0;
static char last_sent_message[BUFFER_SIZE];
static size_t last_sent_len = 0;
static long long cooldown_until_ms = 0;
static long long global_delay_ms = 0;
static long long max_file_size = DEFAULT_MAX_FILE_SIZE;

static pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;
static remote_file_info remote_files[MAX_REMOTE_FILES];
static int remote_file_count = 0;
static volatile int file_list_ready = 0;
static download_slot download_slots[MAX_DOWNLOADS];
static char download_dir[MAX_KEY_PATH];
static volatile int ui_active = 0;

static chat_line *chat_lines = NULL;
static int chat_line_count = 0;
static int chat_line_capacity = 0;
static int chat_scroll_back = 0;

static int get_home_dir(char *out, size_t size);
static void request_file_list(int sock);
static void request_download(int sock, long long id);
static void open_upload_manager(int sock);
static void open_download_browser(int sock);

static struct termios saved_termios;
static volatile sig_atomic_t terminal_is_raw = 0;

static struct termios password_saved_termios;
static volatile sig_atomic_t password_echo_disabled = 0;

static void restore_terminal(void) {
    if (ui_active) {
        fputs("\33[?1049l", stdout);
        fflush(stdout);
        ui_active = 0;
    }
    if (terminal_is_raw) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        terminal_is_raw = 0;
    }
}

static void restore_password_echo(void) {
    if (password_echo_disabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &password_saved_termios);
        password_echo_disabled = 0;
    }
}

static void handle_termination_signal(int sig) {
    restore_password_echo();
    restore_terminal();
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_cleanup_handlers(void) {
    atexit(restore_password_echo);
    atexit(restore_terminal);
    signal(SIGINT, handle_termination_signal);
    signal(SIGTERM, handle_termination_signal);
    signal(SIGHUP, handle_termination_signal);
    signal(SIGQUIT, handle_termination_signal);
}

static void setup_terminal(void) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &saved_termios) != 0) return;

    struct termios raw = saved_termios;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);
    raw.c_iflag &= ~(IXON | ICRNL);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return;

    terminal_is_raw = 1;
}

static int read_password(const char *prompt, char *password, size_t size) {
    printf("%s", prompt);
    fflush(stdout);

    if (isatty(STDIN_FILENO) &&
        tcgetattr(STDIN_FILENO, &password_saved_termios) == 0) {
        struct termios no_echo = password_saved_termios;
        no_echo.c_lflag &= ~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &no_echo) == 0) {
            password_echo_disabled = 1;
        }
    }

    char *result = fgets(password, (int)size, stdin);
    int complete_line = result != NULL && strchr(password, '\n') != NULL;

    restore_password_echo();
    putchar('\n');
    fflush(stdout);

    if (result == NULL) return 0;

    password[strcspn(password, "\r\n")] = '\0';

    if (!complete_line) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
        }
    }

    return 1;
}

static long long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Every frame must be written as one length-prefixed unit.  The receive
   thread answers heartbeats, so sends from both threads are serialized. */
static int client_send(int sock, const void *data, size_t len) {
    pthread_mutex_lock(&send_lock);
    int rc = cchat_send_encrypted(sock, data, len);
    pthread_mutex_unlock(&send_lock);
    return rc;
}

static size_t display_columns(const char *text, size_t len) {
    size_t columns = 0;
    for (size_t i = 0; i < len; i++) {
        if (((unsigned char)text[i] & 0xC0) != 0x80) columns++;
    }
    return columns;
}

static int terminal_columns(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return ws.ws_col;
    }
    return 80;
}

static int terminal_rows(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        return ws.ws_row;
    }
    return 24;
}

static size_t utf8_char_len(const char *text, size_t remaining) {
    unsigned char c = (unsigned char)text[0];
    size_t n = 1;

    if ((c & 0xE0) == 0xC0) n = 2;
    else if ((c & 0xF0) == 0xE0) n = 3;
    else if ((c & 0xF8) == 0xF0) n = 4;

    if (n > remaining) n = 1;
    return n;
}

static void print_limited_columns(const char *text, size_t max_columns) {
    size_t len = strlen(text);
    size_t i = 0;
    size_t columns = 0;

    while (i < len && columns < max_columns) {
        size_t n = utf8_char_len(text + i, len - i);
        fwrite(text + i, 1, n, stdout);
        i += n;
        columns++;
    }
}

static void append_one_chat_line_locked(const char *text, size_t len) {
    if (len == 0) return;

    char *line = malloc(len + 1);
    if (line == NULL) return;

    size_t o = 0;
    int pending_space = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\n' || c == '\r' || c == '\t') {
            pending_space = 1;
            continue;
        }
        if (c < 32 || c == 127) continue;
        if (pending_space && o > 0) line[o++] = ' ';
        pending_space = 0;
        line[o++] = (char)c;
    }
    while (o > 0 && line[o - 1] == ' ') o--;
    line[o] = '\0';

    if (o == 0) {
        free(line);
        return;
    }

    if (chat_line_count >= MAX_CHAT_LINES) {
        free(chat_lines[0].text);
        memmove(&chat_lines[0], &chat_lines[1],
                (size_t)(chat_line_count - 1) * sizeof(chat_lines[0]));
        chat_line_count--;
        if (chat_scroll_back > 0) chat_scroll_back--;
    }

    if (chat_line_count == chat_line_capacity) {
        int new_capacity = chat_line_capacity == 0 ? 256 : chat_line_capacity * 2;
        if (new_capacity > MAX_CHAT_LINES) new_capacity = MAX_CHAT_LINES;

        chat_line *tmp = realloc(chat_lines,
                                 (size_t)new_capacity * sizeof(*chat_lines));
        if (tmp == NULL) {
            free(line);
            return;
        }
        chat_lines = tmp;
        chat_line_capacity = new_capacity;
    }

    chat_lines[chat_line_count++].text = line;
    if (chat_scroll_back > 0) chat_scroll_back++;
}

static void append_chat_line_locked(const char *text, size_t len) {
    size_t start = 0;

    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n') {
            if (i > start) {
                append_one_chat_line_locked(text + start, i - start);
            }
            start = i + 1;
        }
    }

    if (start < len) {
        append_one_chat_line_locked(text + start, len - start);
    }
}

static void draw_prompt_locked(void) {
    int rows = terminal_rows();
    int cols = terminal_columns();

    char prompt[128];
    if (chat_scroll_back > 0) {
        snprintf(prompt, sizeof(prompt), "[%s] (scroll %d): ",
                 current_username, chat_scroll_back);
    } else {
        snprintf(prompt, sizeof(prompt), "[%s]: ", current_username);
    }

    printf("\33[%d;1H\33[2K%s", rows, prompt);

    size_t prompt_columns = display_columns(prompt, strlen(prompt));
    size_t available = prompt_columns < (size_t)cols
        ? (size_t)cols - prompt_columns
        : 0;
    size_t input_columns = display_columns(input_line, input_line_len);
    size_t start = 0;

    if (input_columns > available) {
        size_t skip = input_columns - available;
        while (start < input_line_len && skip > 0) {
            start += utf8_char_len(input_line + start,
                                   input_line_len - start);
            skip--;
        }
    }

    if (start < input_line_len) {
        fwrite(input_line + start, 1, input_line_len - start, stdout);
    }
    fflush(stdout);
}

static void redraw_chat_locked(void) {
    int rows = terminal_rows();
    int cols = terminal_columns();
    int chat_rows = rows - 1;
    if (chat_rows < 1) chat_rows = 1;

    int max_back = chat_line_count - chat_rows;
    if (max_back < 0) max_back = 0;
    if (chat_scroll_back > max_back) chat_scroll_back = max_back;
    if (chat_scroll_back < 0) chat_scroll_back = 0;

    int start = chat_line_count - chat_rows - chat_scroll_back;
    if (start < 0) start = 0;

    fputs("\33[H\33[2J", stdout);
    for (int i = 0; i < chat_rows; i++) {
        int idx = start + i;
        if (idx >= 0 && idx < chat_line_count) {
            print_limited_columns(chat_lines[idx].text, (size_t)cols);
        }
        fputs("\33[K\n", stdout);
    }
    draw_prompt_locked();
    fflush(stdout);
}

/* Adds text to the chat log and redraws the visible viewport.  While a
   full-screen file browser is open only the log is updated; the viewport is
   redrawn when the browser closes. */
static void output_text_locked(const char *text, size_t len) {
    append_chat_line_locked(text, len);
    if (!ui_active) redraw_chat_locked();
}

static void scroll_chat_locked(int delta) {
    int rows = terminal_rows();
    int chat_rows = rows - 1;
    if (chat_rows < 1) chat_rows = 1;

    int max_back = chat_line_count - chat_rows;
    if (max_back < 0) max_back = 0;

    int next = chat_scroll_back + delta;
    if (next < 0) next = 0;
    if (next > max_back) next = max_back;

    if (next != chat_scroll_back) {
        chat_scroll_back = next;
        redraw_chat_locked();
    }
}

static void scroll_chat_pages_locked(int pages) {
    int rows = terminal_rows();
    int chat_rows = rows - 1;
    if (chat_rows < 1) chat_rows = 1;
    scroll_chat_locked(pages * chat_rows);
}

static void notify(const char *text) {
    pthread_mutex_lock(&output_lock);
    output_text_locked(text, strlen(text));
    pthread_mutex_unlock(&output_lock);
}

static void remove_last_char_locked(void) {
    if (input_line_len == 0) return;

    size_t start = input_line_len;
    while (start > 0 && ((unsigned char)input_line[start - 1] & 0xC0) == 0x80) {
        start--;
    }
    if (start > 0) start--;

    input_line_len = start;
    input_line[input_line_len] = '\0';
}

static void init_download_dir(void) {
    char home[MAX_KEY_PATH];
    struct stat st;

    if (get_home_dir(home, sizeof(home)) != 0) {
        snprintf(download_dir, sizeof(download_dir), ".");
        return;
    }

    char cchat_dir[MAX_KEY_PATH];
    snprintf(cchat_dir, sizeof(cchat_dir), "%s/.cchat", home);
    if (mkdir(cchat_dir, 0700) != 0 && errno != EEXIST) {
        snprintf(download_dir, sizeof(download_dir), "%s", home);
        return;
    }

    snprintf(download_dir, sizeof(download_dir), "%s/.cchat/Downloads", home);
    if (mkdir(download_dir, 0755) != 0 && errno != EEXIST) {
        snprintf(download_dir, sizeof(download_dir), "%s", home);
        return;
    }

    if (stat(download_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(download_dir, sizeof(download_dir), "%s", home);
    }
}

static void sanitize_download_name(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c == '/' || c == '\\') c = '_';
        out[o++] = (char)c;
    }
    out[o] = '\0';

    if (o == 0 || strcmp(out, ".") == 0 || strcmp(out, "..") == 0) {
        snprintf(out, cap, "file");
    }
}

static void make_download_path(long long id, const char *name,
                               char *out, size_t cap) {
    char base[256];
    sanitize_download_name(name, base, sizeof(base));

    snprintf(out, cap, "%s/%s", download_dir, base);
    if (access(out, F_OK) != 0) return;

    char stem[256];
    char ext[64];
    snprintf(stem, sizeof(stem), "%s", base);
    ext[0] = '\0';

    char *dot = strrchr(stem, '.');
    if (dot != NULL && dot != stem) {
        snprintf(ext, sizeof(ext), "%s", dot);
        *dot = '\0';
    }

    for (int n = 1; n < 10000; n++) {
        snprintf(out, cap, "%s/%s (%d)%s", download_dir, stem, n, ext);
        if (access(out, F_OK) != 0) return;
    }

    snprintf(out, cap, "%s/%lld_%s", download_dir, id, base);
}

static download_slot *find_download_slot_locked(long long id) {
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        if (download_slots[i].active && download_slots[i].id == id) {
            return &download_slots[i];
        }
    }
    return NULL;
}

static int download_is_active(long long id) {
    pthread_mutex_lock(&file_lock);
    int active = find_download_slot_locked(id) != NULL;
    pthread_mutex_unlock(&file_lock);
    return active;
}

static void download_begin(const char *frame) {
    long long id, size;
    char b64[MAX_B64_NAME];
    if (sscanf(frame + 12, "%lld %lld %511s", &id, &size, b64) != 3) {
        return;
    }

    uint8_t decoded[256];
    size_t decoded_len = 0;
    if (cchat_b64_decode(b64, strlen(b64), decoded,
                         sizeof(decoded) - 1, &decoded_len) != 0) {
        return;
    }
    decoded[decoded_len] = '\0';

    pthread_mutex_lock(&file_lock);

    if (find_download_slot_locked(id) != NULL) {
        pthread_mutex_unlock(&file_lock);
        return;
    }

    download_slot *slot = NULL;
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        if (!download_slots[i].active) {
            slot = &download_slots[i];
            break;
        }
    }

    if (slot == NULL) {
        pthread_mutex_unlock(&file_lock);
        notify("[!] Too many simultaneous downloads; request ignored.");
        return;
    }

    char path[MAX_KEY_PATH];
    make_download_path(id, (const char *)decoded, path, sizeof(path));
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        pthread_mutex_unlock(&file_lock);
        notify("[!] Cannot create the download file.");
        return;
    }

    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    slot->id = id;
    slot->fp = f;
    slot->size = size;
    snprintf(slot->path, sizeof(slot->path), "%s", path);
    snprintf(slot->name, sizeof(slot->name), "%s", (const char *)decoded);

    pthread_mutex_unlock(&file_lock);

    char text[1024];
    snprintf(text, sizeof(text), "[*] Downloading \"%s\" (#%lld)...", slot->name, id);
    notify(text);
}

static void download_data(const char *frame) {
    long long id = atoll(frame + 11);
    const char *b64 = strchr(frame + 11, ' ');
    if (b64 == NULL) return;
    b64++;

    uint8_t data[FILE_CHUNK_SIZE + 4];
    size_t data_len = 0;
    if (cchat_b64_decode(b64, strlen(b64), data,
                         sizeof(data), &data_len) != 0) {
        return;
    }

    pthread_mutex_lock(&file_lock);
    download_slot *slot = find_download_slot_locked(id);
    if (slot == NULL) {
        pthread_mutex_unlock(&file_lock);
        return;
    }

    if (slot->received + (long long)data_len > slot->size) {
        fclose(slot->fp);
        remove(slot->path);
        slot->fp = NULL;
        slot->active = 0;
        pthread_mutex_unlock(&file_lock);
        notify("[!] Download failed: received more data than expected.");
        return;
    }

    if (data_len > 0 && fwrite(data, 1, data_len, slot->fp) != data_len) {
        fclose(slot->fp);
        remove(slot->path);
        slot->fp = NULL;
        slot->active = 0;
        pthread_mutex_unlock(&file_lock);
        notify("[!] Download failed: cannot write to disk.");
        return;
    }
    slot->received += (long long)data_len;
    pthread_mutex_unlock(&file_lock);
}

static void download_end(const char *frame) {
    long long id = atoll(frame + 10);

    pthread_mutex_lock(&file_lock);
    download_slot *slot = find_download_slot_locked(id);
    if (slot == NULL) {
        pthread_mutex_unlock(&file_lock);
        return;
    }

    fflush(slot->fp);
    fclose(slot->fp);
    slot->fp = NULL;
    int complete = slot->received == slot->size;
    char path[MAX_KEY_PATH];
    char name[256];
    long long size = slot->size;
    snprintf(path, sizeof(path), "%s", slot->path);
    snprintf(name, sizeof(name), "%s", slot->name);
    slot->active = 0;
    pthread_mutex_unlock(&file_lock);

    char text[8192];
    if (complete) {
        snprintf(text, sizeof(text), "[File] Saved \"%s\" (%lld bytes) to %s",
                 name, size, path);
    } else {
        snprintf(text, sizeof(text),
                 "[!] Download of \"%s\" is incomplete (saved to %s)",
                 name, path);
    }
    notify(text);
}

static void download_error(const char *frame) {
    long long id = atoll(frame + 10);
    const char *reason = strchr(frame + 10, ' ');
    if (reason != NULL) reason++;
    else reason = "unknown error";

    pthread_mutex_lock(&file_lock);
    download_slot *slot = find_download_slot_locked(id);
    if (slot != NULL) {
        fclose(slot->fp);
        remove(slot->path);
        slot->fp = NULL;
        slot->active = 0;
    }
    pthread_mutex_unlock(&file_lock);

    char text[8192];
    snprintf(text, sizeof(text), "[!] Download #%lld failed: %s", id, reason);
    notify(text);
}

static int handle_file_frame(const char *frame) {
    if (strncmp(frame, "@FILE_ENTRY ", 12) == 0) {
        long long id, size;
        char uploader[MAX_USER_LEN + 1];
        char b64[MAX_B64_NAME];

        if (sscanf(frame + 12, "%lld %lld %10s %511s",
                   &id, &size, uploader, b64) == 4) {
            uint8_t decoded[256];
            size_t decoded_len = 0;
            if (cchat_b64_decode(b64, strlen(b64), decoded,
                                 sizeof(decoded) - 1, &decoded_len) == 0) {
                decoded[decoded_len] = '\0';

                pthread_mutex_lock(&file_lock);
                if (remote_file_count < MAX_REMOTE_FILES) {
                    remote_file_info *rf = &remote_files[remote_file_count++];
                    rf->id = id;
                    rf->size = size;
                    snprintf(rf->uploader, sizeof(rf->uploader), "%s", uploader);
                    snprintf(rf->name, sizeof(rf->name), "%s",
                             (const char *)decoded);
                }
                pthread_mutex_unlock(&file_lock);
            }
        }
        return 1;
    }

    if (strncmp(frame, "@FILE_LIST_END", 14) == 0) {
        pthread_mutex_lock(&file_lock);
        file_list_ready = 1;
        pthread_mutex_unlock(&file_lock);
        return 1;
    }

    if (strncmp(frame, "@FILE_BEGIN ", 12) == 0) {
        download_begin(frame);
        return 1;
    }

    if (strncmp(frame, "@FILE_DATA ", 11) == 0) {
        download_data(frame);
        return 1;
    }

    if (strncmp(frame, "@FILE_END ", 10) == 0) {
        download_end(frame);
        return 1;
    }

    if (strncmp(frame, "@FILE_ERR ", 10) == 0) {
        download_error(frame);
        return 1;
    }

    if (strncmp(frame, "@UPLOAD_ERR ", 12) == 0) {
        char text[8192];
        snprintf(text, sizeof(text), "[!] Upload rejected: %s", frame + 12);
        notify(text);
        return 1;
    }

    return 0;
}

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    size_t bytes_received;

    while (is_running) {
        int rc = cchat_recv_encrypted(sock, buffer, sizeof(buffer) - 1, &bytes_received);
        if (rc <= 0) break;
        buffer[bytes_received] = '\0';

        if (handle_file_frame(buffer)) continue;

        if (strncmp(buffer, "@PING", 5) == 0) {
            const char pong_frame[] = "@PONG\n";
            client_send(sock, pong_frame, sizeof(pong_frame) - 1);
            continue;
        }

        if (strncmp(buffer, "@MAX_FILE_SIZE ", 15) == 0) {
            long long size = atoll(buffer + 15);
            if (size >= 0) {
                pthread_mutex_lock(&output_lock);
                max_file_size = size;
                pthread_mutex_unlock(&output_lock);
            }
            continue;
        }

        if (strncmp(buffer, "@DELAY ", 7) == 0) {
            long long ms = atoll(buffer + 7);
            if (ms < 0) ms = 0;

            pthread_mutex_lock(&output_lock);
            global_delay_ms = ms;
            if (ms == 0) {
                cooldown_until_ms = 0;
            }
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (strncmp(buffer, "@COOLDOWN ", 10) == 0) {
            long long ms = atoll(buffer + 10);
            if (ms > 0) {
                pthread_mutex_lock(&output_lock);
                long long until = monotonic_ms() + ms;
                if (until > cooldown_until_ms) {
                    cooldown_until_ms = until;
                }
                pthread_mutex_unlock(&output_lock);
            }
            continue;
        }

        if (strncmp(buffer, "@REJECT ", 8) == 0) {
            long long ms = atoll(buffer + 8);
            if (ms < 0) ms = 0;

            pthread_mutex_lock(&output_lock);
            cooldown_until_ms = monotonic_ms() + ms;

            if (input_line_len == 0 && last_sent_len > 0) {
                memcpy(input_line, last_sent_message, last_sent_len + 1);
                input_line_len = last_sent_len;
            }
            last_sent_len = 0;

            char text[160];
            snprintf(text, sizeof(text),
                     "[!] Please wait %.1f seconds before sending another message.",
                     ms / 1000.0);
            output_text_locked(text, strlen(text));
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        pthread_mutex_lock(&output_lock);
        output_text_locked(buffer, bytes_received);
        pthread_mutex_unlock(&output_lock);
    }
    return NULL;
}

static void chat_loop(int sock) {
    char formatted_msg[BUFFER_SIZE + MAX_USER_LEN + 10];
    int escape_state = 0;
    char escape_params[16];
    size_t escape_len = 0;

    while (is_running) {
        int open_list = 0;
        pthread_mutex_lock(&file_lock);
        if (file_list_ready) {
            file_list_ready = 0;
            open_list = 1;
        }
        pthread_mutex_unlock(&file_lock);

        if (open_list) {
            open_download_browser(sock);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        int ready = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;

        unsigned char input_byte;
        ssize_t read_rc = read(STDIN_FILENO, &input_byte, 1);
        if (read_rc < 0) {
            if (errno == EINTR) continue;
            is_running = 0;
            break;
        }
        if (read_rc == 0) {
            is_running = 0;
            break;
        }
        int ch = input_byte;

        if (escape_state == 1) {
            if (ch == '[' || ch == 'O') {
                escape_state = 2;
                escape_len = 0;
            } else {
                escape_state = 0;
            }
            continue;
        }
        if (escape_state == 2) {
            if (ch >= 0x40 && ch <= 0x7E) {
                pthread_mutex_lock(&output_lock);
                if (ch == 'A') {
                    scroll_chat_locked(1);
                } else if (ch == 'B') {
                    scroll_chat_locked(-1);
                } else if (ch == '~' && escape_len > 0) {
                    if (escape_params[0] == '5') {
                        scroll_chat_pages_locked(1);
                    } else if (escape_params[0] == '6') {
                        scroll_chat_pages_locked(-1);
                    }
                }
                pthread_mutex_unlock(&output_lock);
                escape_state = 0;
            } else if (escape_len + 1 < sizeof(escape_params)) {
                escape_params[escape_len++] = (char)ch;
            } else {
                escape_state = 0;
            }
            continue;
        }
        if (ch == 27) {
            escape_state = 1;
            continue;
        }

        if (ch == 3) {
            is_running = 0;
            break;
        }

        if (ch == 4) {
            if (input_line_len == 0) {
                is_running = 0;
                break;
            }
            continue;
        }

        if (ch == 12) {
            pthread_mutex_lock(&output_lock);
            redraw_chat_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 15) {
            open_upload_manager(sock);
            continue;
        }

        if (ch == 6) {
            request_file_list(sock);
            continue;
        }

        if (ch == 21) {
            pthread_mutex_lock(&output_lock);
            while (input_line_len > 0) {
                remove_last_char_locked();
            }
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 127 || ch == 8) {
            pthread_mutex_lock(&output_lock);
            remove_last_char_locked();
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            pthread_mutex_lock(&output_lock);

            if (input_line_len == 0) {
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
                continue;
            }

            input_line[input_line_len] = '\0';

            if (strcmp(input_line, "/files") == 0 ||
                strcmp(input_line, "/download") == 0) {
                input_line_len = 0;
                input_line[0] = '\0';
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
                request_file_list(sock);
                continue;
            }

            if (strcmp(input_line, "/upload") == 0) {
                input_line_len = 0;
                input_line[0] = '\0';
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
                open_upload_manager(sock);
                continue;
            }

            if (strncmp(input_line, "/get ", 5) == 0) {
                long long id = atoll(input_line + 5);
                if (id > 0) {
                    input_line_len = 0;
                    input_line[0] = '\0';
                    draw_prompt_locked();
                    pthread_mutex_unlock(&output_lock);
                    request_download(sock, id);
                    continue;
                }
            }

            if (strcmp(input_line, "/help") == 0) {
                input_line_len = 0;
                input_line[0] = '\0';
                const char *help =
                    "Commands: /upload - open the file picker, "
                    "/files - browse and download server files,\n"
                    "/get <id> - download file number <id>.\n"
                    "Keys: Up/Down - scroll chat history, "
                    "PageUp/PageDown - scroll a page,\n"
                    "Ctrl-O - file picker, Ctrl-F - server file list.\n";
                output_text_locked(help, strlen(help));
                pthread_mutex_unlock(&output_lock);
                continue;
            }

            long long now = monotonic_ms();
            if (cooldown_until_ms > now) {
                double wait_seconds = (cooldown_until_ms - now) / 1000.0;

                char text[160];
                snprintf(text, sizeof(text),
                         "[!] Please wait %.1f seconds before sending another message.",
                         wait_seconds);
                output_text_locked(text, strlen(text));
                pthread_mutex_unlock(&output_lock);
                continue;
            }

            char message[BUFFER_SIZE];
            size_t message_len;

            message_len = input_line_len;
            memcpy(message, input_line, message_len + 1);

            memcpy(last_sent_message, message, message_len + 1);
            last_sent_len = message_len;

            snprintf(formatted_msg, sizeof(formatted_msg), "[%s]: %s\n",
                     current_username, message);

            input_line_len = 0;
            input_line[0] = '\0';
            chat_scroll_back = 0;
            cooldown_until_ms = global_delay_ms > 0
                ? monotonic_ms() + global_delay_ms
                : 0;
            output_text_locked(formatted_msg, strlen(formatted_msg));
            pthread_mutex_unlock(&output_lock);

            if (client_send(sock, formatted_msg, strlen(formatted_msg)) <= 0) {
                is_running = 0;
                break;
            }
            continue;
        }

        if (ch >= 32) {
            if (input_line_len < MAX_MSG_LEN) {
                pthread_mutex_lock(&output_lock);
                input_line[input_line_len++] = (char)ch;
                input_line[input_line_len] = '\0';
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
            } else {
                pthread_mutex_lock(&output_lock);
                putchar('\a');
                fflush(stdout);
                pthread_mutex_unlock(&output_lock);
            }
        }
    }
}

static int get_home_dir(char *out, size_t size) {
    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0') {
        int n = snprintf(out, size, "%s", home);
        return (n >= 0 && (size_t)n < size) ? 0 : -1;
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] == '\0') {
        return -1;
    }

    int n = snprintf(out, size, "%s", pw->pw_dir);
    return (n >= 0 && (size_t)n < size) ? 0 : -1;
}

static void format_file_size(long long size, char *out, size_t cap) {
    if (size < 1024) {
        snprintf(out, cap, "%lld B", size);
    } else if (size < 1024LL * 1024) {
        snprintf(out, cap, "%.1f KiB", size / 1024.0);
    } else if (size < 1024LL * 1024 * 1024) {
        snprintf(out, cap, "%.1f MiB", size / (1024.0 * 1024.0));
    } else {
        snprintf(out, cap, "%.1f GiB", size / (1024.0 * 1024.0 * 1024.0));
    }
}

static void join_path(const char *dir, const char *name, char *out, size_t cap) {
    if (strcmp(dir, "/") == 0) {
        snprintf(out, cap, "/%s", name);
    } else {
        snprintf(out, cap, "%s/%s", dir, name);
    }
}

static void parent_path(char *path) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    path[len] = '\0';

    char *slash = strrchr(path, '/');
    if (slash == NULL) {
        snprintf(path, MAX_KEY_PATH, "/");
    } else if (slash == path) {
        path[1] = '\0';
    } else {
        *slash = '\0';
    }
}

static int fm_compare(const void *pa, const void *pb) {
    const fm_entry *a = (const fm_entry *)pa;
    const fm_entry *b = (const fm_entry *)pb;

    if (a->is_dir != b->is_dir) {
        return a->is_dir ? -1 : 1;
    }
    return strcasecmp(a->name, b->name);
}

static int load_directory(const char *path, fm_entry **entries_out,
                          int *count_out) {
    DIR *d = opendir(path);
    if (d == NULL) return -1;

    int cap = 64;
    int count = 0;
    fm_entry *entries = malloc((size_t)cap * sizeof(*entries));
    if (entries == NULL) {
        closedir(d);
        return -1;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0) continue;

        char full[MAX_KEY_PATH];
        join_path(path, de->d_name, full, sizeof(full));

        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (count == cap) {
            int new_cap = cap * 2;
            fm_entry *tmp = realloc(entries,
                                    (size_t)new_cap * sizeof(*entries));
            if (tmp == NULL) break;
            entries = tmp;
            cap = new_cap;
        }

        snprintf(entries[count].name, sizeof(entries[count].name),
                 "%s", de->d_name);
        entries[count].is_dir = S_ISDIR(st.st_mode);
        count++;
    }
    closedir(d);

    qsort(entries, (size_t)count, sizeof(*entries), fm_compare);
    *entries_out = entries;
    *count_out = count;
    return 0;
}

static int selection_index(char (*selected)[MAX_KEY_PATH], int count,
                           const char *path) {
    for (int i = 0; i < count; i++) {
        if (strcmp(selected[i], path) == 0) return i;
    }
    return -1;
}

static void selection_toggle(char (*selected)[MAX_KEY_PATH], int *count,
                             const char *path) {
    int idx = selection_index(selected, *count, path);
    if (idx >= 0) {
        for (int i = idx; i + 1 < *count; i++) {
            memmove(selected[i], selected[i + 1], MAX_KEY_PATH);
        }
        (*count)--;
    } else if (*count < MAX_SELECTED_FILES) {
        snprintf(selected[*count], MAX_KEY_PATH, "%s", path);
        (*count)++;
    }
}

#define UI_KEY_UP 1001
#define UI_KEY_DOWN 1002
#define UI_KEY_LEFT 1003
#define UI_KEY_RIGHT 1004
#define UI_KEY_HOME 1005
#define UI_KEY_END 1006

static int ui_read_key(void) {
    unsigned char c;
    ssize_t n;

    do {
        n = read(STDIN_FILENO, &c, 1);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return -1;

    if (c != 27) return c;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 30000;

    if (select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv) <= 0) {
        return 27;
    }

    unsigned char first;
    do {
        n = read(STDIN_FILENO, &first, 1);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return 27;

    if (first != '[' && first != 'O') return 27;

    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 30000;
    if (select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv) <= 0) {
        return 27;
    }

    unsigned char second;
    do {
        n = read(STDIN_FILENO, &second, 1);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return 27;

    switch (second) {
        case 'A': return UI_KEY_UP;
        case 'B': return UI_KEY_DOWN;
        case 'C': return UI_KEY_RIGHT;
        case 'D': return UI_KEY_LEFT;
        case 'H': return UI_KEY_HOME;
        case 'F': return UI_KEY_END;
        default: return 27;
    }
}

static void enter_ui(void) {
    pthread_mutex_lock(&output_lock);
    ui_active = 1;
    pthread_mutex_unlock(&output_lock);

    fputs("\33[?1049h\33[2J\33[H", stdout);
    fflush(stdout);
}

static void leave_ui(void) {
    fputs("\33[?1049l", stdout);
    fflush(stdout);

    pthread_mutex_lock(&output_lock);
    ui_active = 0;
    redraw_chat_locked();
    pthread_mutex_unlock(&output_lock);
}

static void send_file_path(int sock, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        char text[8192];
        snprintf(text, sizeof(text), "[!] Cannot open file: %s", path);
        notify(text);
        return;
    }

    pthread_mutex_lock(&output_lock);
    long long size_limit = max_file_size;
    pthread_mutex_unlock(&output_lock);

    if ((long long)st.st_size > size_limit) {
        char text[8192];
        char limit[64];
        format_file_size(size_limit, limit, sizeof(limit));
        snprintf(text, sizeof(text),
                 "[!] File \"%s\" is too large (max %s).", path, limit);
        notify(text);
        return;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        char text[8192];
        snprintf(text, sizeof(text), "[!] Cannot open file: %s", path);
        notify(text);
        return;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    char name_b64[MAX_B64_NAME];
    if (cchat_b64_encode((const uint8_t *)base, strlen(base),
                         name_b64, sizeof(name_b64)) < 0) {
        fclose(f);
        notify("[!] File name is too long.");
        return;
    }

    char size_text[64];
    format_file_size((long long)st.st_size, size_text, sizeof(size_text));
    char text[1024];
    snprintf(text, sizeof(text), "[*] Uploading \"%s\" (%s)...",
             base, size_text);
    notify(text);

    char line[BUFFER_SIZE];
    snprintf(line, sizeof(line), "@UPLOAD_BEGIN %lld %s\n",
             (long long)st.st_size, name_b64);
    if (client_send(sock, line, strlen(line)) <= 0) {
        fclose(f);
        is_running = 0;
        return;
    }

    uint8_t data[FILE_CHUNK_SIZE];
    char encoded[4 * ((FILE_CHUNK_SIZE + 2) / 3) + 1];
    size_t n;
    while ((n = fread(data, 1, sizeof(data), f)) > 0) {
        if (cchat_b64_encode(data, n, encoded, sizeof(encoded)) < 0) break;
        snprintf(line, sizeof(line), "@UPLOAD_DATA %s\n", encoded);
        if (client_send(sock, line, strlen(line)) <= 0) {
            fclose(f);
            is_running = 0;
            return;
        }
    }
    fclose(f);

    const char *end = "@UPLOAD_END\n";
    if (client_send(sock, end, strlen(end)) <= 0) {
        is_running = 0;
    }
}

static void send_selected_files(int sock, char (*paths)[MAX_KEY_PATH],
                                int count) {
    for (int i = 0; i < count && is_running; i++) {
        send_file_path(sock, paths[i]);
    }
}

static void draw_upload_ui(const char *cwd, fm_entry *entries, int count,
                           int cursor, int offset,
                           char (*selected)[MAX_KEY_PATH], int selected_count) {
    int cols = terminal_columns();
    int rows = terminal_rows();
    int visible = rows - 4;
    if (visible < 1) visible = 1;

    fputs("\33[H\33[2J", stdout);
    printf("Files: %.*s\n", cols > 8 ? cols - 8 : cols, cwd);
    printf("Selected: %d\n", selected_count);

    if (count == 0) {
        printf("  (empty directory)\n");
    } else {
        int name_width = cols - 6;
        if (name_width < 8) name_width = 8;

        for (int row = 0; row < visible; row++) {
            int idx = offset + row;
            if (idx >= count) break;

            char full[MAX_KEY_PATH];
            join_path(cwd, entries[idx].name, full, sizeof(full));

            int is_selected = selection_index(selected, selected_count, full) >= 0;
            const char *marker = is_selected ? "[x] " : "[ ] ";

            if (idx == cursor) fputs("\33[7m", stdout);
            if (entries[idx].is_dir) {
                int dir_width = name_width - 1;
                if (dir_width < 1) dir_width = 1;
                printf("%.*s/\33[K", dir_width, entries[idx].name);
            } else {
                printf("%s%.*s\33[K", marker, name_width, entries[idx].name);
            }
            if (idx == cursor) fputs("\33[0m", stdout);
            putchar('\n');
        }
    }

    printf("\n[%d/%d]  j/k or arrows: move  h/l: directory\n",
           count > 0 ? cursor + 1 : 0, count);
    printf("space: select  enter: send  q: cancel\n");
    fflush(stdout);
}

static void open_upload_manager(int sock) {
    char (*selected)[MAX_KEY_PATH] =
        calloc(MAX_SELECTED_FILES, MAX_KEY_PATH);
    if (selected == NULL) {
        notify("[!] Out of memory.");
        return;
    }

    int selected_count = 0;
    char cwd[MAX_KEY_PATH];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), ".");
    }

    fm_entry *entries = NULL;
    int count = 0;
    if (load_directory(cwd, &entries, &count) != 0) {
        notify("[!] Cannot read the current directory.");
        free(selected);
        return;
    }

    int cursor = 0;
    int offset = 0;
    int send_files = 0;

    enter_ui();

    while (is_running) {
        draw_upload_ui(cwd, entries, count, cursor, offset,
                       selected, selected_count);

        int key = ui_read_key();
        if (key < 0 || key == 3 || key == 'q' || key == 27) break;

        if (key == 'j' || key == UI_KEY_DOWN) {
            if (count > 0) cursor = (cursor + 1) % count;
        } else if (key == 'k' || key == UI_KEY_UP) {
            if (count > 0) cursor = (cursor - 1 + count) % count;
        } else if (key == 'g' || key == UI_KEY_HOME) {
            cursor = 0;
        } else if (key == 'G' || key == UI_KEY_END) {
            cursor = count > 0 ? count - 1 : 0;
        } else if (key == 'h' || key == UI_KEY_LEFT ||
                   key == 8 || key == 127) {
            parent_path(cwd);
            free(entries);
            entries = NULL;
            if (load_directory(cwd, &entries, &count) != 0) {
                entries = NULL;
                count = 0;
            }
            cursor = 0;
            offset = 0;
        } else if (key == 'l' || key == UI_KEY_RIGHT) {
            if (count > 0 && entries[cursor].is_dir) {
                char next[MAX_KEY_PATH];
                join_path(cwd, entries[cursor].name, next, sizeof(next));

                fm_entry *next_entries = NULL;
                int next_count = 0;
                if (load_directory(next, &next_entries, &next_count) == 0) {
                    free(entries);
                    entries = next_entries;
                    count = next_count;
                    snprintf(cwd, sizeof(cwd), "%s", next);
                    cursor = 0;
                    offset = 0;
                }
            }
        } else if (key == ' ') {
            if (count > 0 && !entries[cursor].is_dir) {
                char full[MAX_KEY_PATH];
                join_path(cwd, entries[cursor].name, full, sizeof(full));
                selection_toggle(selected, &selected_count, full);
            }
        } else if (key == '\n' || key == '\r') {
            if (selected_count > 0) {
                send_files = 1;
                break;
            }

            if (count > 0) {
                if (entries[cursor].is_dir) {
                    char next[MAX_KEY_PATH];
                    join_path(cwd, entries[cursor].name, next, sizeof(next));

                    fm_entry *next_entries = NULL;
                    int next_count = 0;
                    if (load_directory(next, &next_entries, &next_count) == 0) {
                        free(entries);
                        entries = next_entries;
                        count = next_count;
                        snprintf(cwd, sizeof(cwd), "%s", next);
                        cursor = 0;
                        offset = 0;
                    }
                } else {
                    char full[MAX_KEY_PATH];
                    join_path(cwd, entries[cursor].name, full, sizeof(full));
                    selection_toggle(selected, &selected_count, full);
                    send_files = 1;
                    break;
                }
            }
        }

        int visible = terminal_rows() - 4;
        if (visible < 1) visible = 1;
        if (cursor < offset) offset = cursor;
        if (cursor >= offset + visible) offset = cursor - visible + 1;
    }

    free(entries);
    leave_ui();

    if (send_files && selected_count > 0 && is_running) {
        send_selected_files(sock, selected, selected_count);
    }
    free(selected);
}

static void request_file_list(int sock) {
    pthread_mutex_lock(&file_lock);
    remote_file_count = 0;
    file_list_ready = 0;
    pthread_mutex_unlock(&file_lock);

    const char *msg = "@FILE_LIST\n";
    if (client_send(sock, msg, strlen(msg)) <= 0) {
        is_running = 0;
        return;
    }
    notify("[*] Requesting file list from server...");
}

static void draw_download_ui(const char *saved_to, remote_file_info *files,
                             int count, int cursor, int offset,
                             unsigned char *selected, int selected_count) {
    int cols = terminal_columns();
    int rows = terminal_rows();
    int visible = rows - 4;
    if (visible < 1) visible = 1;

    fputs("\33[H\33[2J", stdout);
    printf("Server files (saved to: %.*s)\n",
           cols > 28 ? cols - 28 : cols, saved_to);
    printf("Selected: %d\n", selected_count);

    if (count == 0) {
        printf("  (no files on the server yet)\n");
    } else {
        int name_width = cols - 42;
        if (name_width < 10) name_width = 10;

        for (int row = 0; row < visible; row++) {
            int idx = offset + row;
            if (idx >= count) break;

            char size_text[64];
            format_file_size(files[idx].size, size_text, sizeof(size_text));

            if (idx == cursor) fputs("\33[7m", stdout);
            printf("%s#%lld %.*s (%s) by %s\33[K",
                   selected[idx] ? "[x] " : "[ ] ",
                   files[idx].id, name_width, files[idx].name,
                   size_text, files[idx].uploader);
            if (idx == cursor) fputs("\33[0m", stdout);
            putchar('\n');
        }
    }

    printf("\n[%d/%d]  j/k or arrows: move\n",
           count > 0 ? cursor + 1 : 0, count);
    printf("space: select  enter: download  q: cancel\n");
    fflush(stdout);
}

static void request_download(int sock, long long id) {
    if (download_is_active(id)) {
        notify("[*] That file is already being downloaded.");
        return;
    }

    int active_count = 0;
    pthread_mutex_lock(&file_lock);
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        if (download_slots[i].active) active_count++;
    }
    pthread_mutex_unlock(&file_lock);

    if (active_count >= MAX_DOWNLOADS) {
        notify("[!] Too many simultaneous downloads.");
        return;
    }

    char msg[64];
    snprintf(msg, sizeof(msg), "@FILE_GET %lld\n", id);
    if (client_send(sock, msg, strlen(msg)) <= 0) {
        is_running = 0;
    }
}

static void open_download_browser(int sock) {
    pthread_mutex_lock(&file_lock);
    int count = remote_file_count;
    remote_file_info *files =
        calloc(count > 0 ? (size_t)count : 1, sizeof(*files));
    if (files != NULL && count > 0) {
        memcpy(files, remote_files, (size_t)count * sizeof(*files));
    }
    pthread_mutex_unlock(&file_lock);

    if (files == NULL) {
        notify("[!] Out of memory.");
        return;
    }

    unsigned char *selected =
        calloc(count > 0 ? (size_t)count : 1, sizeof(*selected));
    if (selected == NULL) {
        free(files);
        notify("[!] Out of memory.");
        return;
    }

    int cursor = 0;
    int offset = 0;
    int selected_count = 0;
    int do_download = 0;

    enter_ui();

    while (is_running) {
        draw_download_ui(download_dir, files, count, cursor, offset,
                         selected, selected_count);

        int key = ui_read_key();
        if (key < 0 || key == 3 || key == 'q' || key == 27) break;

        if (key == 'j' || key == UI_KEY_DOWN) {
            if (count > 0) cursor = (cursor + 1) % count;
        } else if (key == 'k' || key == UI_KEY_UP) {
            if (count > 0) cursor = (cursor - 1 + count) % count;
        } else if (key == 'g' || key == UI_KEY_HOME) {
            cursor = 0;
        } else if (key == 'G' || key == UI_KEY_END) {
            cursor = count > 0 ? count - 1 : 0;
        } else if (key == ' ') {
            if (count > 0) {
                selected[cursor] = selected[cursor] ? 0 : 1;
                selected_count += selected[cursor] ? 1 : -1;
            }
        } else if (key == '\n' || key == '\r') {
            if (count > 0) {
                if (selected_count == 0) {
                    selected[cursor] = 1;
                    selected_count = 1;
                }
                do_download = 1;
                break;
            }
        }

        int visible = terminal_rows() - 4;
        if (visible < 1) visible = 1;
        if (cursor < offset) offset = cursor;
        if (cursor >= offset + visible) offset = cursor - visible + 1;
    }

    leave_ui();

    if (do_download && is_running) {
        for (int i = 0; i < count && is_running; i++) {
            if (selected[i]) request_download(sock, files[i].id);
        }
    }

    free(selected);
    free(files);
}

static char *trim_input(char *text) {
    while (*text == ' ' || *text == '\t') text++;

    char *end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static int parse_server_address(const char *input, char *ip, size_t ip_size,
                                int *port) {
    char copy[MAX_ADDRESS_LEN];
    if (strlen(input) >= sizeof(copy)) return -1;
    snprintf(copy, sizeof(copy), "%s", input);

    char *colon = strrchr(copy, ':');
    if (colon == NULL || colon == copy || colon[1] == '\0') return -1;

    *colon = '\0';

    char *end = NULL;
    errno = 0;
    long value = strtol(colon + 1, &end, 10);
    if (errno != 0 || end == colon + 1 || *end != '\0' ||
        value < 1 || value > 65535) {
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, copy, &addr) != 1) return -1;
    if (strlen(copy) >= ip_size) return -1;

    snprintf(ip, ip_size, "%s", copy);
    *port = (int)value;
    return 0;
}

static int ensure_cchat_dir(char *dir, size_t size) {
    char home[MAX_KEY_PATH];

    if (get_home_dir(home, sizeof(home)) != 0) {
        printf("[Error]: Cannot determine home directory.\n");
        return -1;
    }

    int n = snprintf(dir, size, "%s/.cchat", home);
    if (n < 0 || (size_t)n >= size) {
        printf("[Error]: Home directory path is too long.\n");
        return -1;
    }

    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        printf("[Error]: Cannot create directory %s: %s\n",
               dir, strerror(errno));
        return -1;
    }

    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        printf("[Error]: %s is not a directory.\n", dir);
        return -1;
    }

    return 0;
}

static int build_key_path(const char *server_ip, int port,
                          char *path, size_t size) {
    char dir[MAX_KEY_PATH];

    if (ensure_cchat_dir(dir, sizeof(dir)) != 0) return -1;

    int n = snprintf(path, size, "%s/%s:%d", dir, server_ip, port);
    if (n < 0 || (size_t)n >= size) {
        printf("[Error]: Key file path is too long.\n");
        return -1;
    }

    return 0;
}

static int save_server_key(const char *server_ip, int port, const char *key) {
    char path[MAX_KEY_PATH];
    if (build_key_path(server_ip, port, path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        printf("[Error]: Cannot save key file %s: %s\n",
               path, strerror(errno));
        return -1;
    }

    int ok = fprintf(f, "%s\n", key) >= 0;
    if (fclose(f) != 0) ok = 0;

    if (!ok) {
        printf("[Error]: Cannot write key file %s.\n", path);
        return -1;
    }

    if (chmod(path, 0600) != 0) {
        printf("[Warning]: Cannot restrict permissions on %s: %s\n",
               path, strerror(errno));
    }

    printf("Saved server %s:%d to %s\n", server_ip, port, path);
    return 0;
}

static int load_saved_server_key(const char *server_ip, int port,
                                 char *key, size_t size) {
    char path[MAX_KEY_PATH];
    if (build_key_path(server_ip, port, path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        printf("[Error]: Cannot open key file %s: %s\n",
               path, strerror(errno));
        return -1;
    }

    if (fgets(key, (int)size, f) == NULL) {
        fclose(f);
        printf("[Error]: Key file is empty: %s\n", path);
        return -1;
    }
    fclose(f);

    key[strcspn(key, "\r\n")] = '\0';
    if (key[0] == '\0') {
        printf("[Error]: Key file is empty: %s\n", path);
        return -1;
    }

    if (strlen(key) > CHAT_KEY_MAX) {
        printf("[Error]: Key in %s is too long (max %d bytes).\n",
               path, CHAT_KEY_MAX);
        return -1;
    }

    return 0;
}

static int prompt_server_address(char *ip, size_t ip_size, int *port) {
    char line[MAX_ADDRESS_LEN];

    for (;;) {
        printf("Server address (IP:PORT, e.g. 127.0.0.1:8080): ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) return -1;

        if (strchr(line, '\n') == NULL) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {
            }
        }

        line[strcspn(line, "\r\n")] = '\0';
        char *value = trim_input(line);
        if (*value == '\0') continue;

        if (parse_server_address(value, ip, ip_size, port) == 0) return 0;

        printf("Invalid address. Use IPv4:PORT, for example 127.0.0.1:8080.\n");
    }
}

static int prompt_server_key(char *key, size_t size) {
    char temp[CHAT_KEY_MAX + 2];

    for (;;) {
        memset(temp, 0, sizeof(temp));

        if (!read_password("Enter server key: ", temp, sizeof(temp))) {
            memset(temp, 0, sizeof(temp));
            return -1;
        }

        if (temp[0] == '\0') {
            printf("Key cannot be empty.\n");
            continue;
        }

        if (strlen(temp) > CHAT_KEY_MAX) {
            printf("Key is too long (max %d bytes).\n", CHAT_KEY_MAX);
            memset(temp, 0, sizeof(temp));
            continue;
        }

        snprintf(key, size, "%s", temp);
        memset(temp, 0, sizeof(temp));
        return 0;
    }
}

static int compare_server_names(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int list_saved_servers(char names[][MAX_SERVER_NAME], int max_names) {
    char dir[MAX_KEY_PATH];

    if (ensure_cchat_dir(dir, sizeof(dir)) != 0) return 0;

    DIR *d = opendir(dir);
    if (d == NULL) return 0;

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(d)) != NULL && count < max_names) {
        if (entry->d_name[0] == '.') continue;
        if (strlen(entry->d_name) >= MAX_SERVER_NAME) continue;

        char ip[64];
        int port;
        if (parse_server_address(entry->d_name, ip, sizeof(ip), &port) != 0) {
            continue;
        }

        char path[MAX_KEY_PATH];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        snprintf(names[count], MAX_SERVER_NAME, "%s", entry->d_name);
        count++;
    }

    closedir(d);

    if (count > 1) {
        qsort(names, (size_t)count, MAX_SERVER_NAME, compare_server_names);
    }
    return count;
}

static int add_saved_server(char *ip, size_t ip_size, int *port,
                            char *key, size_t key_size) {
    printf("\nAdd a new server\n");

    if (prompt_server_address(ip, ip_size, port) != 0) return -1;
    if (prompt_server_key(key, key_size) != 0) return -1;

    if (save_server_key(ip, *port, key) != 0) {
        memset(key, 0, key_size);
        return -1;
    }

    return 0;
}

static int direct_connection(char *ip, size_t ip_size, int *port,
                             char *key, size_t key_size) {
    printf("\nDirect connection\n");

    if (prompt_server_address(ip, ip_size, port) != 0) return -1;
    if (prompt_server_key(key, key_size) != 0) return -1;

    return 0;
}

static int choose_server(char *ip, size_t ip_size, int *port,
                         char *key, size_t key_size) {
    char names[MAX_SAVED_SERVERS][MAX_SERVER_NAME];

    for (;;) {
        int count = list_saved_servers(names, MAX_SAVED_SERVERS);

        if (count == 0) {
            printf("No saved servers.\n");
        } else {
            printf("Saved servers:\n");
            for (int i = 0; i < count; i++) {
                printf("  %d) %s\n", i + 1, names[i]);
            }
        }

        printf("  a) Add a new server\n");
        printf("  b) Direct connection\n");
        printf("  q) Quit\n");
        printf("Choose: ");
        fflush(stdout);

        char line[64];
        if (fgets(line, sizeof(line), stdin) == NULL) return -1;

        line[strcspn(line, "\r\n")] = '\0';
        char *choice = trim_input(line);
        if (*choice == '\0') continue;

        if (strcasecmp(choice, "a") == 0) {
            if (add_saved_server(ip, ip_size, port, key, key_size) == 0) {
                return 0;
            }
            continue;
        }

        if (strcasecmp(choice, "b") == 0) {
            if (direct_connection(ip, ip_size, port, key, key_size) == 0) {
                return 0;
            }
            continue;
        }

        if (strcasecmp(choice, "q") == 0) return -1;

        char *end = NULL;
        errno = 0;
        long number = strtol(choice, &end, 10);
        if (errno == 0 && end != choice && *end == '\0' &&
            number >= 1 && number <= count) {
            char saved_ip[64];
            int saved_port;

            if (parse_server_address(names[number - 1], saved_ip,
                                     sizeof(saved_ip), &saved_port) != 0) {
                printf("Invalid saved server entry.\n");
                continue;
            }

            if (load_saved_server_key(saved_ip, saved_port,
                                      key, key_size) != 0) {
                continue;
            }

            snprintf(ip, ip_size, "%s", saved_ip);
            *port = saved_port;
            return 0;
        }

        printf("Invalid choice.\n");
    }
}

static void load_history_into_buffer(int sock) {
    char buffer[BUFFER_SIZE];
    size_t bytes_received;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    while (1) {
        int rc = cchat_recv_encrypted(sock, buffer, sizeof(buffer) - 1, &bytes_received);
        if (rc <= 0) break;
        buffer[bytes_received] = '\0';

        if (strncmp(buffer, "@PING", 5) == 0) {
            const char pong_frame[] = "@PONG\n";
            client_send(sock, pong_frame, sizeof(pong_frame) - 1);
            continue;
        }

        if (strncmp(buffer, "@MAX_FILE_SIZE ", 15) == 0) {
            long long size = atoll(buffer + 15);
            if (size >= 0) max_file_size = size;
            continue;
        }

        if (strncmp(buffer, "@DELAY ", 7) == 0) {
            long long ms = atoll(buffer + 7);
            if (ms < 0) ms = 0;
            global_delay_ms = ms;
            continue;
        }
        if (strncmp(buffer, "@COOLDOWN ", 10) == 0) {
            long long ms = atoll(buffer + 10);
            if (ms > 0) {
                long long until = monotonic_ms() + ms;
                if (until > cooldown_until_ms) {
                    cooldown_until_ms = until;
                }
            }
            continue;
        }
        if (buffer[0] == '@') continue;

        append_chat_line_locked(buffer, bytes_received);
    }

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
}

int main(void) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    pthread_t recv_thread;
    char server_ip[64];
    int port = 0;
    char server_key[CHAT_KEY_MAX + 2];

    install_cleanup_handlers();
    init_download_dir();

    for (;;) {
        memset(server_key, 0, sizeof(server_key));

        if (choose_server(server_ip, sizeof(server_ip), &port,
                          server_key, sizeof(server_key)) != 0) {
            return 0;
        }

        if (cchat_set_key(server_key) != 0) {
            printf("[Error]: Invalid key for %s:%d.\n", server_ip, port);
            memset(server_key, 0, sizeof(server_key));
            continue;
        }
        memset(server_key, 0, sizeof(server_key));

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
            printf("Invalid address / Address not supported\n");
            continue;
        }

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("Socket creation error\n");
            return -1;
        }

        printf("Connecting to %s:%d...\n", server_ip, port);
        fflush(stdout);

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            printf("Connection failed: %s\n", strerror(errno));
            close(sock);
            sock = 0;
            continue;
        }

        break;
    }

    int choice = 0;
    while (choice != 1 && choice != 2) {
        printf("\n1. Sign In\n2. Sign Up\nChoose action (1 or 2): ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            choice = 0;
        }
        while (getchar() != '\n');
    }

    memset(current_username, 0, MAX_USER_LEN);
    printf("Enter username (max 9 characters): ");
    if (fgets(current_username, MAX_USER_LEN, stdin) != NULL) {
        if (strchr(current_username, '\n') == NULL) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {
            }
        }
        current_username[strcspn(current_username, "\r\n")] = 0;
    }

    char password[MAX_PASS_LEN];
    memset(password, 0, MAX_PASS_LEN);
    if (!read_password("Enter password (max 63 characters): ", password, sizeof(password))) {
        close(sock);
        return 0;
    }

    if (choice == 2) {
        char confirmation[MAX_PASS_LEN];

        for (;;) {
            memset(confirmation, 0, sizeof(confirmation));
            if (!read_password("Confirm password: ", confirmation, sizeof(confirmation))) {
                close(sock);
                return 0;
            }

            if (strcmp(password, confirmation) == 0) break;

            printf("[Error]: Passwords do not match. Try again.\n");
            memset(password, 0, sizeof(password));
            if (!read_password("Enter password (max 63 characters): ", password, sizeof(password))) {
                close(sock);
                return 0;
            }
        }

        memset(confirmation, 0, sizeof(confirmation));
    }

    char auth_data[sizeof(int) + MAX_USER_LEN + MAX_PASS_LEN];
    memset(auth_data, 0, sizeof(auth_data));
    memcpy(auth_data, &choice, sizeof(int));
    memcpy(auth_data + sizeof(int), current_username, MAX_USER_LEN);
    memcpy(auth_data + sizeof(int) + MAX_USER_LEN, password, MAX_PASS_LEN);

    if (client_send(sock, auth_data, sizeof(auth_data)) <= 0) {
        perror("Failed to send credentials");
        close(sock);
        return 1;
    }

    char response[64];
    size_t response_len = 0;
    int auth_rc = cchat_recv_encrypted(sock, response, sizeof(response) - 1, &response_len);
    if (auth_rc <= 0) {
        printf("Server disconnected or did not respond.\n");
        close(sock);
        return 0;
    }
    response[response_len] = '\0';

    if (strncmp(response, "OK", 2) != 0) {
        if (strcmp(response, "ERR_USER_EXISTS") == 0) {
            printf("\n[Error]: User already exists.\n");
        } else if (strcmp(response, "ERR_BANNED") == 0) {
            printf("\n[Error]: You are permanently banned for spamming.\n");
        } else {
            printf("\n[Error]: Invalid username or password.\n");
        }
        close(sock);
        return 0;
    }

    if (choice == 2) {
        printf("\nRegistration successful! Entering chat...\n");
    } else {
        printf("\nLogin successful! Loading chat history...\n");
    }

    load_history_into_buffer(sock);

    setup_terminal();

    pthread_mutex_lock(&output_lock);
    redraw_chat_locked();
    pthread_mutex_unlock(&output_lock);

    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        restore_terminal();
        perror("Failed to create thread");
        close(sock);
        return 1;
    }

    chat_loop(sock);

    is_running = 0;
    pthread_mutex_lock(&output_lock);
    putchar('\n');
    fflush(stdout);
    pthread_mutex_unlock(&output_lock);

    restore_terminal();
    close(sock);
    return 0;
}
