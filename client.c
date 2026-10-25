#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

/*
 * The same key must be defined in server.c.  It is embedded in the source on
 * purpose, so it protects messages in transit but is not a secret.
 */
#define CHAT_ENCRYPTION_KEY "YourKey"
#include "crypto.h"

#define BUFFER_SIZE 1024
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512

int is_running = 1;
char current_username[MAX_USER_LEN];

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    size_t bytes_received;

    while (is_running) {
        int rc = cchat_recv_encrypted(sock, buffer, sizeof(buffer) - 1, &bytes_received);
        if (rc <= 0) break;
        buffer[bytes_received] = '\0';
        printf("\r\33[2K%s", buffer);
        printf("[%s]: ", current_username);
        fflush(stdout);
    }
    return NULL;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    pthread_t recv_thread;
    char server_ip[64];
    int port;

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
    printf("Enter password (max 63 characters): ");
    if (fgets(password, MAX_PASS_LEN, stdin) != NULL) {
        password[strcspn(password, "\r\n")] = 0;
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

    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sock) < 0) {
        perror("Failed to create thread");
        return 1;
    }

    char raw_msg[BUFFER_SIZE];
    char formatted_msg[BUFFER_SIZE + MAX_USER_LEN + 10];

    printf("[%s]: ", current_username);
    fflush(stdout);

    while (is_running) {
        if (fgets(raw_msg, BUFFER_SIZE, stdin) == NULL) {
            is_running = 0;
            break;
        }

        if (strlen(raw_msg) > MAX_MSG_LEN) {
            printf("[!] Message too long (limit %d characters). Truncated.\n", MAX_MSG_LEN);
            raw_msg[MAX_MSG_LEN] = '\n';
            raw_msg[MAX_MSG_LEN + 1] = '\0';
        }

        raw_msg[strcspn(raw_msg, "\r\n")] = 0;
        if (strlen(raw_msg) == 0) {
            printf("[%s]: ", current_username);
            fflush(stdout);
            continue;
        }

        snprintf(formatted_msg, sizeof(formatted_msg), "[%s]: %s\n", current_username, raw_msg);
        if (cchat_send_encrypted(sock, formatted_msg, strlen(formatted_msg)) <= 0) {
            break;
        }

        printf("[%s]: ", current_username);
        fflush(stdout);
    }

    close(sock);
    return 0;
}
