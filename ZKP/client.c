#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "zpie.h"
#include "zpie_helpers.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9000

int main()
{
    setup_keys keys = perform_setup(&circuit);
    proof p = generate_proof(&circuit, keys.pk);

    // Send the proof to the server over a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Client: Connection failed");
        return 1;
    }

    // Send proof size and proof data
    write(sock, &p, sizeof(proof));
    close(sock);

    printf("Client: Proof sent to server.\n");
    return 0;
}
