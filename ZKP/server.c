#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "zpie.h"
#include "zpie_helpers.h"

#define PORT 9000

int main()
{
    // Setup the circuit on the server side (can reuse same circuit structure)
    setup_keys keys = perform_setup(&circuit);

    // Start server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("Server: Waiting for connection...\n");
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Server: accept");
        return 1;
    }

    // Receive the proof
    proof p;
    read(client_fd, &p, sizeof(proof));
    close(client_fd);

    // Verify the proof
    if (verify_proof(&circuit, p, keys.vk)) {
        printf("Server: ✅ Proof verified.\n");
    } else {
        printf("Server: ❌ Proof failed.\n");
    }

    return 0;
}
