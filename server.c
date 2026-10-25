#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>

/*
 * The same key must be defined in client.c.  It is embedded in the source on
 * purpose, so it protects messages in transit but is not a secret.
 */
#define CHAT_ENCRYPTION_KEY "cchat-embedded-key-2026-do-not-use-in-production"
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

unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
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

void save_to_history(const char *msg) {
    FILE *f = fopen(HISTORY_FILE, "a");
    if (f) {
        fprintf(f, "%s", msg);
        fclose(f);
    }
}

int main() {
    int PORT = load_or_create_config();

    int server_fd, new_socket, client_sockets[MAX_CLIENTS], max_sd, sd, activity;
    size_t msg_len = 0;
    char client_usernames[MAX_CLIENTS][MAX_USER_LEN];
    int addrlen;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE];
    fd_set readfds;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
        memset(client_usernames[i], 0, MAX_USER_LEN);
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
                send_history(new_socket);

                char join_msg[BUFFER_SIZE];
                snprintf(join_msg, sizeof(join_msg), "[Server]: User %s joined the chat.\n", auth_user);
                save_to_history(join_msg);

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
                    save_to_history(leave_msg);

                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        int cs = client_sockets[j];
                        if (cs != 0 && cs != sd) {
                            cchat_send_encrypted(cs, leave_msg, strlen(leave_msg));
                        }
                    }

                    close(sd);
                    client_sockets[i] = 0;
                    memset(client_usernames[i], 0, MAX_USER_LEN);
                } else {
                    buffer[msg_len] = '\0';
                    
                    if (msg_len > MAX_MSG_LEN) {
                        buffer[MAX_MSG_LEN] = '\0';
                    }

                    save_to_history(buffer);

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
