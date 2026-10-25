#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define MAX_USER_LEN 10
#define MAX_PASS_LEN 64
#define MAX_MSG_LEN 512
#define SECRET_KEY "YourKey"

int is_running = 1;
char current_username[MAX_USER_LEN];

void xor_crypt(char *data, size_t len) {
    size_t key_len = strlen(SECRET_KEY);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= SECRET_KEY[i % key_len];
    }
}

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (is_running && (bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        xor_crypt(buffer, bytes_received);
        buffer[bytes_received] = '\0';
        
        printf("\r\33[2K%s", buffer);
        if (buffer[bytes_received - 1] != '\n') {
            printf("\n");
        }
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

    if (send(sock, &choice, sizeof(int), 0) < 0) {
        perror("Failed to send action");
        close(sock);
        return 1;
    }
    if (send(sock, current_username, MAX_USER_LEN, 0) < 0) {
        perror("Failed to send username");
        close(sock);
        return 1;
    }
    if (send(sock, password, MAX_PASS_LEN, 0) < 0) {
        perror("Failed to send password");
        close(sock);
        return 1;
    }

    char response[64];
    memset(response, 0, sizeof(response));
    int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_read <= 0) {
        printf("Server disconnected or did not respond.\n");
        close(sock);
        return 0;
    }

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
        if (fgets(raw_msg, BUFFER_SIZE, stdin) != NULL) {
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
            
            size_t msg_len = strlen(formatted_msg);
            xor_crypt(formatted_msg, msg_len);
            send(sock, formatted_msg, msg_len, 0);
            
            printf("[%s]: ", current_username);
            fflush(stdout);
        }
    }

    close(sock);
    return 0;
}
