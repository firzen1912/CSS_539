#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "zpie.h"
#include "zpie_helpers.h"

#define PORT 9000
#define RESPONSE_SIZE 16

int main()
{
    setup_keys keys = perform_setup(&circuit);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Server: Socket creation failed");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Server: Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("Server: Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Server: Waiting for connection on port %d...\n", PORT);

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Server: Accept failed");
        close(server_fd);
        return 1;
    }

    printf("Server: Client connected.\n");

    proof p;
    ssize_t received = recv(client_fd, &p, sizeof(proof), 0);
    if (received <= 0) {
        perror("Server: Failed to receive proof");
        close(client_fd);
        close(server_fd);
        return 1;
    }

    char response[RESPONSE_SIZE];
    if (verify_proof(&circuit, p, keys.vk)) {
        printf("Server: Proof verified.\n");
        snprintf(response, RESPONSE_SIZE, "OK");
    } else {
        printf("Server: Proof failed.\n");
        snprintf(response, RESPONSE_SIZE, "FAIL");
    }

    // Send response back to client
    if (send(client_fd, response, strlen(response), 0) < 0) {
        perror("Server: Failed to send response");
    } else {
        printf("Server: Sent response to client: %s\n", response);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
