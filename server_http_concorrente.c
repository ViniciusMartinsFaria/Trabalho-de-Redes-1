#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define BUFFER_SIZE 4096

void *handle_client(void *arg) {
    int clientSock = *(int *)arg;
    free(arg);

    char buffer[BUFFER_SIZE];
    int bytesRead;

    while (1) {
        bytesRead = recv(clientSock, buffer, BUFFER_SIZE - 1, 0);
        if (bytesRead <= 0) {
            break;
        }

        buffer[bytesRead] = '\0';

        printf("Requisição recebida:\n%s\n", buffer);

        const char *response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 19\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "Servidor ativo!\n";

        send(clientSock, response, strlen(response), 0);

        
        if (strstr(buffer, "Connection: close") != NULL) {
            break;
        }

    }

    close(clientSock);
    printf("Conexão encerrada com o cliente.\n");
    return NULL;
}

int main(int argc, const char **argv)
{
    int serverPort = 5000;
    int rc;
    struct sockaddr_in serverSa;
    struct sockaddr_in clientSa;
    socklen_t clientSaSize;
    int on = 1;

    int s = socket(PF_INET, SOCK_STREAM, 0);
    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&serverSa, 0, sizeof(serverSa));
    serverSa.sin_family = AF_INET;
    serverSa.sin_addr.s_addr = htonl(INADDR_ANY);
    serverSa.sin_port = htons(serverPort);

    rc = bind(s, (struct sockaddr *)&serverSa, sizeof(serverSa));
    if (rc < 0)
    {
        perror("bind failed");
        exit(1);
    }

    rc = listen(s, 10);
    if (rc < 0)
    {
        perror("listen failed");
        exit(1);
    }

    printf("Servidor ouvindo na porta %d...\n", serverPort);

    while (1)
    {
        clientSaSize = sizeof(clientSa);
        int *clientSock = malloc(sizeof(int));
        *clientSock = accept(s, (struct sockaddr *)&clientSa, &clientSaSize);

        if (*clientSock < 0)
        {
            perror("accept failed");
            free(clientSock);
            continue;
        }

        printf("Cliente conectado: %s\n", inet_ntoa(clientSa.sin_addr));

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, clientSock);
        pthread_detach(tid);
    }

    close(s);
    return 0;
}