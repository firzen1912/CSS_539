#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "zpie.h"
#include "zpie_helpers.h"

#define SERVER_PORT 9000
#define RESPONSE_BUFFER_SIZE 1024

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];

    setup_keys keys = perform_setup(&circuit);
    proof p = generate_proof(&circuit, keys.pk);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Client: Socket creation failed");
        return 1;
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Client: Invalid address/ Address not supported: %s\n", server_ip);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Client: Connection failed");
        close(sock);
        return 1;
    }

    if (write(sock, &p, sizeof(proof)) < 0) {
        perror("Client: Failed to send proof");
        close(sock);
        return 1;
    }

    printf("Client: Proof sent to server. Waiting for response...\n");

    char response[RESPONSE_BUFFER_SIZE] = {0};
    ssize_t n = read(sock, response, sizeof(response) - 1);
    if (n < 0) {
        perror("Client: Failed to read response from server");
    } else if (n == 0) {
        printf("Client: Server closed the connection.\n");
    } else {
        response[n] = '\0'; // Null-terminate the response string
        printf("Client: Received response from server: %s\n", response);
    }

    close(sock);
    return 0;
}
