#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>

/*
 * The same key must be defined in server.c.  It is embedded in the source on
 * purpose, so it protects messages in transit but is not a secret.
 */
#define CHAT_ENCRYPTION_KEY "ILoveYourMom"
#include "crypto.h"

#define BUFFER_SIZE 1024
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512

static volatile sig_atomic_t is_running = 1;
char current_username[MAX_USER_LEN];

static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static char input_line[BUFFER_SIZE];
static size_t input_line_len = 0;

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

    /* Discard the rest of an overlong password line. */
    if (!complete_line) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* discard */
        }
    }

    return 1;
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

/* Erases the prompt and the partially typed line, including wrapped rows. */
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

        /* Ignore escape sequences such as arrow keys. */
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

        if (ch == 3) { /* Ctrl-C */
            is_running = 0;
            break;
        }

        if (ch == 4) { /* Ctrl-D */
            if (input_line_len == 0) {
                is_running = 0;
                break;
            }
            continue;
        }

        if (ch == 12) { /* Ctrl-L */
            pthread_mutex_lock(&output_lock);
            printf("\33[2J\33[H");
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 21) { /* Ctrl-U */
            pthread_mutex_lock(&output_lock);
            while (input_line_len > 0) {
                remove_last_char_locked();
            }
            clear_input_area_locked();
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == 127 || ch == 8) { /* Backspace */
            pthread_mutex_lock(&output_lock);
            remove_last_char_locked();
            clear_input_area_locked();
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            char message[BUFFER_SIZE];
            size_t message_len = 0;
            int send_message = 0;

            pthread_mutex_lock(&output_lock);
            if (input_line_len > 0) {
                input_line[input_line_len] = '\0';
                message_len = input_line_len;
                memcpy(message, input_line, message_len + 1);
                input_line_len = 0;
                input_line[0] = '\0';
                putchar('\n');
                send_message = 1;
            } else {
                clear_input_area_locked();
            }
            draw_prompt_locked();
            pthread_mutex_unlock(&output_lock);

            if (send_message) {
                snprintf(formatted_msg, sizeof(formatted_msg), "[%s]: %s\n",
                         current_username, message);
                if (cchat_send_encrypted(sock, formatted_msg, strlen(formatted_msg)) <= 0) {
                    is_running = 0;
                    break;
                }
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

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    pthread_t recv_thread;
    char server_ip[64];
    int port;

    install_cleanup_handlers();

    printf("Enter server IP address (e.g., 127.0.0.1): ");
    if (scanf("%63s", server_ip) != 1) return 1;

    printf("Enter server port: ");
    if (scanf("%d", &port) != 1) return 1;
    while (getchar() != '\n');

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address / Address not supported\n");
        return -1;
    }

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
    printf("----------------------------------------\n");

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
