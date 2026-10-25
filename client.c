#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <pwd.h>

#include "crypto.h"

#define BUFFER_SIZE 1024
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512
#define MAX_HISTORY_DISPLAY 50
#define MAX_KEY_PATH 4096

static volatile sig_atomic_t is_running = 1;
char current_username[MAX_USER_LEN];

static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static char input_line[BUFFER_SIZE];
static size_t input_line_len = 0;
static char last_sent_message[BUFFER_SIZE];
static size_t last_sent_len = 0;
static long long cooldown_until_ms = 0;
static long long global_delay_ms = 0;

static struct termios saved_termios;
static volatile sig_atomic_t terminal_is_raw = 0;

static struct termios password_saved_termios;
static volatile sig_atomic_t password_echo_disabled = 0;

static void restore_terminal(void) {
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

static void clear_input_area_locked(void) {
    int columns = terminal_columns();
    size_t prompt_columns = strlen(current_username) + 4;
    size_t total = prompt_columns + display_columns(input_line, input_line_len);
    int rows = total > 0 ? (int)((total - 1) / (size_t)columns) : 0;

    fputs("\r", stdout);
    for (int i = 0; i < rows; i++) {
        fputs("\33[1A", stdout);
    }
    fputs("\33[J", stdout);
}

static void draw_prompt_locked(void) {
    printf("[%s]: %s", current_username, input_line);
    fflush(stdout);
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

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    size_t bytes_received;

    while (is_running) {
        int rc = cchat_recv_encrypted(sock, buffer, sizeof(buffer) - 1, &bytes_received);
        if (rc <= 0) break;
        buffer[bytes_received] = '\0';

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
            clear_input_area_locked();

            if (input_line_len == 0 && last_sent_len > 0) {
                memcpy(input_line, last_sent_message, last_sent_len + 1);
                input_line_len = last_sent_len;
            }
            last_sent_len = 0;

            printf("[!] Please wait %.1f seconds before sending another message.\n",
                   ms / 1000.0);
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        pthread_mutex_lock(&output_lock);
        clear_input_area_locked();
        fwrite(buffer, 1, bytes_received, stdout);
        if (bytes_received == 0 || buffer[bytes_received - 1] != '\n') {
            putchar('\n');
        }
        draw_prompt_locked();
        pthread_mutex_unlock(&output_lock);
    }
    return NULL;
}

static void chat_loop(int sock) {
    char formatted_msg[BUFFER_SIZE + MAX_USER_LEN + 10];
    int escape_state = 0;

    while (is_running) {
        int ch = fgetc(stdin);

        if (ch == EOF) {
            if (ferror(stdin) && errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            is_running = 0;
            break;
        }

        if (escape_state) {
            if (escape_state == 1 && ch == '[') {
                escape_state = 2;
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
            printf("\33[2J\33[H");
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 21) {
            pthread_mutex_lock(&output_lock);
            while (input_line_len > 0) {
                remove_last_char_locked();
            }
            clear_input_area_locked();
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 127 || ch == 8) {
            pthread_mutex_lock(&output_lock);
            remove_last_char_locked();
            clear_input_area_locked();
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            pthread_mutex_lock(&output_lock);

            if (input_line_len == 0) {
                clear_input_area_locked();
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
                continue;
            }

            long long now = monotonic_ms();
            if (cooldown_until_ms > now) {
                double wait_seconds = (cooldown_until_ms - now) / 1000.0;

                clear_input_area_locked();
                printf("[!] Please wait %.1f seconds before sending another message.\n",
                       wait_seconds);
                draw_prompt_locked();
                pthread_mutex_unlock(&output_lock);
                continue;
            }

            char message[BUFFER_SIZE];
            size_t message_len;

            input_line[input_line_len] = '\0';
            message_len = input_line_len;
            memcpy(message, input_line, message_len + 1);

            memcpy(last_sent_message, message, message_len + 1);
            last_sent_len = message_len;

            input_line_len = 0;
            input_line[0] = '\0';
            cooldown_until_ms = global_delay_ms > 0
                ? monotonic_ms() + global_delay_ms
                : 0;
            putchar('\n');
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);

            snprintf(formatted_msg, sizeof(formatted_msg), "[%s]: %s\n",
                     current_username, message);
            if (cchat_send_encrypted(sock, formatted_msg, strlen(formatted_msg)) <= 0) {
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
                if (terminal_is_raw) {
                    putchar(ch);
                    fflush(stdout);
                }
                pthread_mutex_unlock(&output_lock);
            } else if (terminal_is_raw) {
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

static int load_server_key(const char *server_ip, int port) {
    char home[MAX_KEY_PATH];
    char dir[MAX_KEY_PATH];
    char path[MAX_KEY_PATH];

    if (get_home_dir(home, sizeof(home)) != 0) {
        printf("[Error]: Cannot determine home directory.\n");
        return -1;
    }

    int n = snprintf(dir, sizeof(dir), "%s/.cchat", home);
    if (n < 0 || (size_t)n >= sizeof(dir)) {
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

    n = snprintf(path, sizeof(path), "%s/%s:%d", dir, server_ip, port);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        printf("[Error]: Key file path is too long.\n");
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        printf("[Error]: Key file not found: %s\n", path);
        printf("Create it and put the server encryption key in it.\n");
        return -1;
    }

    char key[CHAT_KEY_MAX + 2];
    if (fgets(key, sizeof(key), f) == NULL) {
        fclose(f);
        printf("[Error]: Key file is empty: %s\n", path);
        return -1;
    }
    fclose(f);

    key[strcspn(key, "\r\n")] = '\0';
    if (key[0] == '\0') {
        printf("[Error]: Key file is empty: %s\n", path);
        memset(key, 0, sizeof(key));
        return -1;
    }

    if (strlen(key) > CHAT_KEY_MAX) {
        printf("[Error]: Key in %s is too long (max %d bytes).\n",
               path, CHAT_KEY_MAX);
        memset(key, 0, sizeof(key));
        return -1;
    }

    int rc = cchat_set_key(key);
    memset(key, 0, sizeof(key));
    if (rc != 0) {
        printf("[Error]: Invalid key in %s.\n", path);
        return -1;
    }

    return 0;
}

static void download_full_history(int sock, const char *server_ip, int port) {
    char home[MAX_KEY_PATH];
    char out_path[MAX_KEY_PATH];

    if (get_home_dir(home, sizeof(home)) != 0) {
        printf("[Error]: Cannot determine home directory.\n");
        return;
    }

    snprintf(out_path, sizeof(out_path), "%s/%s:%d", home, server_ip, port);
    FILE *f = fopen(out_path, "w");
    if (!f) {
        printf("[Error]: Cannot create history output file %s: %s\n", out_path, strerror(errno));
        return;
    }

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

        if (strncmp(buffer, "@DELAY ", 7) == 0 ||
            strncmp(buffer, "@COOLDOWN ", 10) == 0) {
            continue;
        }

        fwrite(buffer, 1, bytes_received, f);
    }

    fclose(f);
    printf("History saved to %s\n", out_path);
}

static void load_and_display_recent_history(int sock) {
    char lines[MAX_HISTORY_DISPLAY][BUFFER_SIZE];
    int count = 0;
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

        if (count < MAX_HISTORY_DISPLAY) {
            snprintf(lines[count], BUFFER_SIZE, "%s", buffer);
            count++;
        } else {
            for (int i = 1; i < MAX_HISTORY_DISPLAY; i++) {
                strcpy(lines[i - 1], lines[i]);
            }
            snprintf(lines[MAX_HISTORY_DISPLAY - 1], BUFFER_SIZE, "%s", buffer);
        }
    }

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    for (int i = 0; i < count; i++) {
        fputs(lines[i], stdout);
        if (lines[i][strlen(lines[i]) - 1] != '\n') {
            putchar('\n');
        }
    }
}

int main(int argc, char *argv[]) {
    int export_history = 0;
    if (argc > 1 && strcmp(argv[1], "--history") == 0) {
        export_history = 1;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    pthread_t recv_thread;
    char server_ip[64];
    char address_input[128];
    int port;

    install_cleanup_handlers();

    printf("Enter server address (e.g., 127.0.0.1:8080): ");
    if (scanf("%127s", address_input) != 1) return 1;
    while (getchar() != '\n');

    char *colon = strrchr(address_input, ':');
    if (colon == NULL) {
        printf("Invalid format. Please use IP:PORT (e.g., 127.0.0.1:8080)\n");
        return -1;
    }

    *colon = '\0';
    snprintf(server_ip, sizeof(server_ip), "%s", address_input);
    port = atoi(colon + 1);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address / Address not supported\n");
        return -1;
    }

    if (port <= 0 || port > 65535) {
        printf("Invalid port\n");
        return -1;
    }

    if (load_server_key(server_ip, port) != 0) {
        return 1;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection failed\n");
        return -1;
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

    if (cchat_send_encrypted(sock, auth_data, sizeof(auth_data)) <= 0) {
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

    if (export_history) {
        printf("\nLogin successful! Downloading chat history...\n");
        download_full_history(sock, server_ip, port);
        close(sock);
        return 0;
    }

    if (choice == 2) {
        printf("\nRegistration successful! Entering chat...\n");
    } else {
        printf("\nLogin successful! Loading chat history...\n");
    }
    printf("----------------------------------------\n");

    load_and_display_recent_history(sock);

    setup_terminal();

    pthread_mutex_lock(&output_lock);
    draw_prompt_locked();
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
