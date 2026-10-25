#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>

/*
 * The same key must be defined in client.c.  It is embedded in the source on
 * purpose, so it protects messages in transit but is not a secret.
 */
#define CHAT_ENCRYPTION_KEY "YourKey"
#include "crypto.h"

#define DEFAULT_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512

#define USERS_FILE "users.txt"
#define HISTORY_FILE "history.txt"
#define CONFIG_FILE "host.conf"
#define BANNED_FILE "banned.txt"
#define HISTORY_CONFIG_FILE "history.conf"
#define DELAY_CONFIG_FILE "delay.conf"

/* history.conf: number of history entries to keep (0 = unlimited).
   delay.conf: global delay in seconds for all users (0 = disabled). */
#define MAX_DELAY_SECONDS 86400
#define SPAM_REPEAT_LIMIT 5

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

static int is_banned(const char *username) {
    FILE *f = fopen(BANNED_FILE, "r");
    if (!f) return 0;

    char line[MAX_USER_LEN + 2];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, username) == 0) {
            found = 1;
            break;
        }
    }
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

int handle_auth(int client_sock, char *out_username) {
    int action = 0;
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
    char auth_data[sizeof(int) + MAX_USER_LEN + MAX_PASS_LEN];
    size_t auth_len = 0;

    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(auth_data, 0, sizeof(auth_data));

    if (cchat_recv_encrypted(client_sock, auth_data, sizeof(auth_data), &auth_len) != 1) {
        return 0;
    }
    if (auth_len != sizeof(auth_data)) return 0;

    memcpy(&action, auth_data, sizeof(int));
    memcpy(username, auth_data + sizeof(int), MAX_USER_LEN);
    memcpy(password, auth_data + sizeof(int) + MAX_USER_LEN, MAX_PASS_LEN);

    username[MAX_USER_LEN - 1] = '\0';
    password[MAX_PASS_LEN - 1] = '\0';

    if (action != 1 && action != 2) return 0;

    if (is_banned(username)) {
        char *msg = "ERR_BANNED";
        cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
        return 0;
    }

    unsigned long p_hash = hash_password(password);

    FILE *f = fopen(USERS_FILE, "r");
    int user_exists = 0;

    if (f) {
        char f_user[MAX_USER_LEN];
        unsigned long f_hash;
        while (fscanf(f, "%s %lu", f_user, &f_hash) == 2) {
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
            return 0;
        } else {
            f = fopen(USERS_FILE, "a");
            if (!f) {
                char *msg = "ERR_SERVER";
                cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
                return 0;
            }
            fprintf(f, "%s %lu\n", username, p_hash);
            fclose(f);

            char *msg = "OK";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            strcpy(out_username, username);
            return 1;
        }
    } else {
        if (!user_exists) {
            char *msg = "ERR_INVALID_CREDENTIALS";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            return 0;
        }

        f = fopen(USERS_FILE, "r");
        if (!f) return 0;

        char f_user[MAX_USER_LEN];
        unsigned long f_hash;
        int authenticated = 0;
        while (fscanf(f, "%s %lu", f_user, &f_hash) == 2) {
            if (strcmp(f_user, username) == 0 && f_hash == p_hash) {
                authenticated = 1;
                break;
            }
        }
        fclose(f);

        if (authenticated) {
            char *msg = "OK";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            strcpy(out_username, username);
            return 1;
        } else {
            char *msg = "ERR_INVALID_CREDENTIALS";
            cchat_send_encrypted(client_sock, msg, strlen(msg) + 1);
            return 0;
        }
    }
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

int main() {
    int PORT = load_or_create_config();
    long long history_limit = load_nonnegative_config(HISTORY_CONFIG_FILE, 0);
    long long delay_seconds = load_nonnegative_config(DELAY_CONFIG_FILE, 0);

    if (delay_seconds > MAX_DELAY_SECONDS) {
        printf("Delay in %s is too large, using %d seconds.\n",
               DELAY_CONFIG_FILE, MAX_DELAY_SECONDS);
        delay_seconds = MAX_DELAY_SECONDS;
    }
    long long rate_limit_ms = delay_seconds * 1000;

    trim_history(history_limit);

    printf("History limit: %lld messages (0 = unlimited)\n", history_limit);
    printf("Global delay: %lld seconds\n", delay_seconds);

    int server_fd, new_socket, client_sockets[MAX_CLIENTS], max_sd, sd, activity;
    size_t msg_len = 0;
    char client_usernames[MAX_CLIENTS][MAX_USER_LEN];
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
        memset(client_usernames[i], 0, MAX_USER_LEN);
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

            char auth_user[MAX_USER_LEN];
            memset(auth_user, 0, sizeof(auth_user));

            if (handle_auth(new_socket, auth_user)) {
                printf("Client %s successfully authorized!\n", auth_user);

                char delay_msg[64];
                snprintf(delay_msg, sizeof(delay_msg), "@DELAY %lld\n", rate_limit_ms);
                cchat_send_encrypted(new_socket, delay_msg, strlen(delay_msg));

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

                char join_msg[BUFFER_SIZE];
                snprintf(join_msg, sizeof(join_msg), "[Server]: User %s joined the chat.\n", auth_user);
                save_to_history(join_msg, history_limit);

                for (int j = 0; j < MAX_CLIENTS; j++) {
                    int cs = client_sockets[j];
                    if (cs != 0) {
                        cchat_send_encrypted(cs, join_msg, strlen(join_msg));
                    }
                }

                int added = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_sockets[i] == 0) {
                        client_sockets[i] = new_socket;
                        strcpy(client_usernames[i], auth_user);
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
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];

            if (client_sockets[i] != 0 && FD_ISSET(sd, &readfds)) {
                int msg_rc = cchat_recv_encrypted(sd, buffer, sizeof(buffer) - 1, &msg_len);
                
                if (msg_rc <= 0) {
                    printf("Client %s disconnected.\n", client_usernames[i]);
                    
                    char leave_msg[BUFFER_SIZE];
                    snprintf(leave_msg, sizeof(leave_msg), "[Server]: User %s left the chat.\n", client_usernames[i]);
                    save_to_history(leave_msg, history_limit);

                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        int cs = client_sockets[j];
                        if (cs != 0 && cs != sd) {
                            cchat_send_encrypted(cs, leave_msg, strlen(leave_msg));
                        }
                    }

                    close(sd);
                    client_sockets[i] = 0;
                    memset(client_usernames[i], 0, MAX_USER_LEN);
                    client_last_message[i][0] = '\0';
                    client_repeat_count[i] = 0;
                } else {
                    buffer[msg_len] = '\0';
                    
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

                    if (client_repeat_count[i] > 0 &&
                        strcmp(client_last_message[i], buffer) == 0) {
                        client_repeat_count[i]++;
                    } else {
                        snprintf(client_last_message[i], sizeof(client_last_message[i]), "%s", buffer);
                        client_repeat_count[i] = 1;
                    }

                    if (client_repeat_count[i] >= SPAM_REPEAT_LIMIT) {
                        ban_username(client_usernames[i]);

                        char ban_msg[BUFFER_SIZE];
                        snprintf(ban_msg, sizeof(ban_msg),
                                 "[Server]: You have been permanently banned for spamming.\n");
                        cchat_send_encrypted(sd, ban_msg, strlen(ban_msg));
                        printf("Client %s permanently banned for spamming.\n", client_usernames[i]);

                        char leave_msg[BUFFER_SIZE];
                        snprintf(leave_msg, sizeof(leave_msg),
                                 "[Server]: User %s left the chat.\n", client_usernames[i]);
                        save_to_history(leave_msg, history_limit);

                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            int cs = client_sockets[j];
                            if (cs != 0 && cs != sd) {
                                cchat_send_encrypted(cs, leave_msg, strlen(leave_msg));
                            }
                        }

                        close(sd);
                        client_sockets[i] = 0;
                        memset(client_usernames[i], 0, MAX_USER_LEN);
                        client_last_message[i][0] = '\0';
                        client_repeat_count[i] = 0;
                        continue;
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

                    save_to_history(buffer, history_limit);

                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        int cs = client_sockets[j];
                        if (cs != 0 && cs != sd) {
                            cchat_send_encrypted(cs, buffer, strlen(buffer));
                        }
                    }
                }
            }
        }
    }
    return 0;
}
