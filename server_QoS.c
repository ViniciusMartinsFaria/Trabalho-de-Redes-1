/* server_qos.c

 * Integrantes:
 *  Vinícius Martins Faria
 *  Tiago Campos de Andrade
 *  Douglas da Silva Marques
 *
 * Servidor HTTP/1.1 concorrente (pthreads) com QoS por IP.
 * Este código foi construído apartir do código base disponível em:
 *  https://www.ibm.com/docs/en/zos/3.1.0?topic=applications-example-ipv4-tcp-server-program
 *
 * Uso:
 *   ./server_qos [porta] [arquivo_clientes] [max_kbps]
 * Exemplo:
 *   ./server_qos 5000 clients.txt 4000
 *
 * Arquivo clients.txt tem linhas no formato:
 *   192.168.0.5 2000
 *   10.0.0.7 500
 *
 * Diretório de conteúdo: ./www
 *
 * Observações:
 *  - HTML (*.html) é servido SEM limitação de taxa.
 *  - Outros objetos (images, binários, etc.) são servidos respeitando kbps.
 *  - Se IP não está no arquivo, kbps padrão = 1000.
 *  - Várias conexões do mesmo IP dividem a taxa entre si.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>

#define BUFFER_SIZE 8192
#define DEFAULT_PORT 5000
#define DEFAULT_CLIENTS_FILE "clients.txt"
#define DEFAULT_SERVER_MAX_KBPS 1000000 /* muito grande por padrão */
#define DEFAULT_UNREGISTERED_KBPS 1000

/* Estruturas para controle por IP */
typedef struct ip_entry_s {
    char ip[64];
    int configured_kbps;   /* valor do arquivo clients.txt */
    int active_connections;/* número de conexões ativas desse IP */
    struct timeval last_request_time; /* para estimativa RTT simples */
    double last_rtt_estimate; /* em segundos */
    struct ip_entry_s *next;
} ip_entry_t;

/* cabeça da lista */
ip_entry_t *ip_list = NULL;
pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/* soma das taxas alocadas (configuradas) — usada para admissão */
int server_max_kbps = DEFAULT_SERVER_MAX_KBPS;

/* função utilitária: current time in seconds (double) */
static double now_seconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

/* busca ou cria entrada IP */
ip_entry_t *get_or_create_ip_entry(const char *ip) {
    pthread_mutex_lock(&ip_list_mutex);
    ip_entry_t *p = ip_list;
    while (p) {
        if (strcmp(p->ip, ip) == 0) {
            pthread_mutex_unlock(&ip_list_mutex);
            return p;
        }
        p = p->next;
    }
    /* não achou -> cria com kbps padrão */
    ip_entry_t *n = malloc(sizeof(ip_entry_t));
    strncpy(n->ip, ip, sizeof(n->ip)-1);
    n->ip[sizeof(n->ip)-1] = '\0';
    n->configured_kbps = DEFAULT_UNREGISTERED_KBPS;
    n->active_connections = 0;
    n->last_rtt_estimate = 0.0;
    n->next = ip_list;
    ip_list = n;
    pthread_mutex_unlock(&ip_list_mutex);
    return n;
}

/* carrega arquivo clients.txt */
void load_clients_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Aviso: não encontrou %s. Usando kbps padrão %d para IPs não cadastrados.\n",
                path, DEFAULT_UNREGISTERED_KBPS);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char ip[64];
        int kbps;
        if (sscanf(line, "%63s %d", ip, &kbps) == 2) {
            pthread_mutex_lock(&ip_list_mutex);
            ip_entry_t *p = ip_list;
            int found = 0;
            while (p) {
                if (strcmp(p->ip, ip) == 0) {
                    p->configured_kbps = kbps;
                    found = 1;
                    break;
                }
                p = p->next;
            }
            if (!found) {
                ip_entry_t *n = malloc(sizeof(ip_entry_t));
                strncpy(n->ip, ip, sizeof(n->ip)-1);
                n->ip[sizeof(n->ip)-1] = '\0';
                n->configured_kbps = kbps;
                n->active_connections = 0;
                n->last_rtt_estimate = 0.0;
                n->next = ip_list;
                ip_list = n;
            }
            pthread_mutex_unlock(&ip_list_mutex);
        }
    }
    fclose(f);
}

/* calcula total de kbps configurados (soma por IP configurado) */
int total_configured_kbps() {
    int total = 0;
    pthread_mutex_lock(&ip_list_mutex);
    ip_entry_t *p = ip_list;
    while (p) {
        total += p->configured_kbps;
        p = p->next;
    }
    pthread_mutex_unlock(&ip_list_mutex);
    return total;
}

/* função para enviar arquivo com taxa limitada (kbps). 
 * kbps_to_use é a taxa total disponível para este IP; se há N conexões ativas
 * a função deve dividir entre elas antes de chamar (faça kbps_per_connection).
 */
int send_file_rate_limited(int sock, int fd, off_t filesize, int kbps_per_conn) {
    /* bytes por segundo */
    double bytes_per_sec = (kbps_per_conn * 1000.0) / 8.0;
    if (bytes_per_sec <= 0) bytes_per_sec = 1;
    const size_t chunk = 4096; /* tamanho por envio */
    char buffer[chunk];
    off_t sent = 0;
    while (sent < filesize) {
        ssize_t toread = (filesize - sent) > (off_t)chunk ? (ssize_t)chunk : (ssize_t)(filesize - sent);
        ssize_t r = read(fd, buffer, toread);
        if (r <= 0) {
            if (r == 0) break;
            perror("read file");
            return -1;
        }
        ssize_t total_written = 0;
        while (total_written < r) {
            ssize_t w = send(sock, buffer + total_written, r - total_written, 0);
            if (w < 0) {
                perror("send");
                return -1;
            }
            total_written += w;
        }
        sent += r;
        double secs = (double)r / bytes_per_sec;
        if (secs > 0) {
            long usec = (long)(secs * 1e6);
            if (usec > 0) usleep(usec);
        }
    }
    return 0;
}

/* envia arquivo sem limitação (método direto) */
int send_file_unlimited(int sock, int fd, off_t filesize) {
    const size_t chunk = 4096;
    char buffer[chunk];
    off_t sent = 0;
    while (sent < filesize) {
        ssize_t toread = (filesize - sent) > (off_t)chunk ? (ssize_t)chunk : (ssize_t)(filesize - sent);
        ssize_t r = read(fd, buffer, toread);
        if (r <= 0) {
            if (r == 0) break;
            perror("read file");
            return -1;
        }
        ssize_t total_written = 0;
        while (total_written < r) {
            ssize_t w = send(sock, buffer + total_written, r - total_written, 0);
            if (w < 0) {
                perror("send");
                return -1;
            }
            total_written += w;
        }
        sent += r;
    }
    return 0;
}

/* retorna extensão em minúsculas */
void get_lower_ext(const char *path, char *ext_out, size_t ext_len) {
    ext_out[0] = '\0';
    const char *p = strrchr(path, '.');
    if (!p) return;
    strncpy(ext_out, p+1, ext_len-1);
    ext_out[ext_len-1] = '\0';
    for (size_t i=0;i<strlen(ext_out);i++) {
        if (ext_out[i] >= 'A' && ext_out[i] <= 'Z') ext_out[i] += 32;
    }
}

/* simples map de content-type por extensão */
const char *guess_content_type(const char *path) {
    char ext[32];
    get_lower_ext(path, ext, sizeof(ext));
    if (strcmp(ext, "html")==0) return "text/html";
    if (strcmp(ext, "htm")==0) return "text/html";
    if (strcmp(ext, "jpg")==0 || strcmp(ext,"jpeg")==0) return "image/jpeg";
    if (strcmp(ext, "png")==0) return "image/png";
    if (strcmp(ext, "gif")==0) return "image/gif";
    if (strcmp(ext, "css")==0) return "text/css";
    if (strcmp(ext, "js")==0) return "application/javascript";
    if (strcmp(ext, "txt")==0) return "text/plain";
    return "application/octet-stream";
}

/* sanitiza path e retorna caminho real dentro ./www, evitando ../ */
int build_safe_path(const char *uri, char *out_path, size_t out_len) {
    char rel[1024];
    if (strcmp(uri, "/") == 0 || strlen(uri) == 0) {
        snprintf(rel, sizeof(rel), "www/index.html");
    } else {
        /* remove leading '/' */
        if (uri[0] == '/') snprintf(rel, sizeof(rel), "www/%s", uri+1);
        else snprintf(rel, sizeof(rel), "www/%s", uri);
    }
    /* simplista: rejeita .. ocorrências */
    if (strstr(rel, "..") != NULL) return -1;
    /* opcional: realpath para garantir */
    char realbuf[PATH_MAX];
    if (realpath(rel, realbuf) == NULL) {
        return -1;
    }
    /* garantir que o realpath começa com o cwd + /www */
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return -1;
    char wwwroot[PATH_MAX];
    snprintf(wwwroot, sizeof(wwwroot), "%s/www", cwd);
    if (strncmp(realbuf, wwwroot, strlen(wwwroot)) != 0) {
        return -1;
    }
    strncpy(out_path, realbuf, out_len-1);
    out_path[out_len-1] = '\0';
    return 0;
}

/* parse simples da request: extrai método e uri */
void parse_request_line(const char *req, char *method, size_t mlen, char *uri, size_t ulen) {
    method[0] = '\0';
    uri[0] = '\0';
    /* pegar a primeira linha */
    const char *p = strchr(req, '\r');
    size_t n = p ? (size_t)(p - req) : strlen(req);
    char line[1024];
    if (n >= sizeof(line)) n = sizeof(line)-1;
    strncpy(line, req, n);
    line[n] = '\0';
    sscanf(line, "%s %s", method, uri);
}

/* busca header especifico na requisição (case-insensitive) */
int header_contains(const char *req, const char *header) {
    /* procura header seguido de ":" */
    const char *p = strcasestr(req, header);
    if (!p) return 0;
    const char *colon = strchr(p, ':');
    if (!colon) return 0;
    return 1;
}

/* envia resposta simples de erro */
void send_simple_response(int clientSock, int code, const char *reason, const char *body) {
    char header[1024];
    int content_len = body ? strlen(body) : 0;
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        code, reason, content_len);
    send(clientSock, header, n, 0);
    if (content_len > 0) send(clientSock, body, content_len, 0);
}

/* função que processa EACH connection (thread) */
void *handle_client(void *arg) {
    int clientSock = *(int *)arg;
    free(arg);
    char addrbuf[INET_ADDRSTRLEN];
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    if (getpeername(clientSock, (struct sockaddr *)&peer, &plen) == 0) {
        inet_ntop(AF_INET, &peer.sin_addr, addrbuf, sizeof(addrbuf));
    } else {
        strncpy(addrbuf, "unknown", sizeof(addrbuf));
    }
    printf("Nova thread: cliente %s\n", addrbuf);

    /* obter ip_entry e incrementar active_connections (admitir) */
    ip_entry_t *entry = get_or_create_ip_entry(addrbuf);

    /* Admissão simples: verificar soma das taxas configuradas não excede server_max_kbps.*/
    int total_kbps = total_configured_kbps();
    if (total_kbps > server_max_kbps) {
        /* envia 503 e fecha */
        send_simple_response(clientSock, 503, "Service Unavailable", "Server at capacity\n");
        close(clientSock);
        printf("Conexão de %s rejeitada por capacidade.\n", addrbuf);
        return NULL;
    }

    /* agora incrementa contador de conexões ativas sob lock */
    pthread_mutex_lock(&ip_list_mutex);
    entry->active_connections++;
    pthread_mutex_unlock(&ip_list_mutex);

    char buffer[BUFFER_SIZE + 1];
    ssize_t bytesRead;
    /* loop para conexões persistentes (HTTP/1.1 keep-alive por padrão) */
    while (1) {
        /* receber cabeçalho (simplista): ler até encontrar \r\n\r\n ou timeout */
        bytesRead = recv(clientSock, buffer, BUFFER_SIZE, 0);
        if (bytesRead <= 0) break;
        buffer[bytesRead] = '\0';
        printf("Requisição recebida de %s:\n%s\n", addrbuf, buffer);

        /* parse básico */
        char method[16], uri[512];
        parse_request_line(buffer, method, sizeof(method), uri, sizeof(uri));
        if (strlen(method) == 0) {
            send_simple_response(clientSock, 400, "Bad Request", "Malformed request\n");
            break;
        }

        /* atualizar estimativa RTT simples: diferença entre agora e last_request_time */
        struct timeval now;
        gettimeofday(&now, NULL);
        pthread_mutex_lock(&ip_list_mutex);
        if (entry->last_request_time.tv_sec != 0) {
            double delta = (now.tv_sec - entry->last_request_time.tv_sec) + (now.tv_usec - entry->last_request_time.tv_usec)/1e6;
            entry->last_rtt_estimate = delta;
            /* exibimos no servidor */
            printf("[RTT estimate for %s] %.6f s\n", entry->ip, entry->last_rtt_estimate);
        }
        entry->last_request_time = now;
        pthread_mutex_unlock(&ip_list_mutex);

        /* decidir se é GET/HEAD */
        if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
            send_simple_response(clientSock, 501, "Not Implemented", "Only GET and HEAD supported\n");
            /* se Connection: close no header, fechamos */
            if (header_contains(buffer, "Connection: close")) break;
            else continue;
        }

        /* mapear URI em caminho seguro */
        char safe_path[PATH_MAX];
        if (build_safe_path(uri, safe_path, sizeof(safe_path)) != 0) {
            send_simple_response(clientSock, 403, "Forbidden", "Invalid path\n");
            if (header_contains(buffer, "Connection: close")) break;
            else continue;
        }

        /* open file e obter tamanho */
        int fd = open(safe_path, O_RDONLY);
        if (fd < 0) {
            send_simple_response(clientSock, 404, "Not Found", "File not found\n");
            if (header_contains(buffer, "Connection: close")) break;
            else continue;
        }
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            send_simple_response(clientSock, 500, "Internal Server Error", "stat failed\n");
            if (header_contains(buffer, "Connection: close")) break;
            else continue;
        }
        off_t filesize = st.st_size;

        /* decidir content-type */
        const char *ctype = guess_content_type(safe_path);

        /* construir e enviar header HTTP */
        char header[1024];
        int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Connection: %s\r\n"
            "\r\n",
            ctype, (long)filesize,
            header_contains(buffer, "Connection: close") ? "close" : "keep-alive");
        send(clientSock, header, header_len, 0);

        /* se method == HEAD, não envia o body */
        if (strcmp(method, "HEAD") == 0) {
            close(fd);
            if (header_contains(buffer, "Connection: close")) break;
            else continue;
        }

        /* se é HTML -> enviar sem limitação */
        char ext[32];
        get_lower_ext(safe_path, ext, sizeof(ext));
        int is_html = (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0);

        /* obter kbps configurado para esse IP */
        pthread_mutex_lock(&ip_list_mutex);
        int configured_kbps = entry->configured_kbps;
        int active_conns = entry->active_connections > 0 ? entry->active_connections : 1;
        pthread_mutex_unlock(&ip_list_mutex);

        if (is_html) {
            /* enviar sem rate limiting */
            send_file_unlimited(clientSock, fd, filesize);
        } else {
            /* aplica QoS: divide configured_kbps por active_conns */
            int kbps_per_conn = configured_kbps / active_conns;
            if (kbps_per_conn <= 0) kbps_per_conn = 1;
            send_file_rate_limited(clientSock, fd, filesize, kbps_per_conn);
        }

        close(fd);

        /* se header Connection: close -> fecha */
        if (header_contains(buffer, "Connection: close")) break;
        /* caso contrário, continua esperando próxima requisição na mesma conexão */
    }

    /* conexão encerrada: decrementar contador de conexões ativas */
    pthread_mutex_lock(&ip_list_mutex);
    if (entry->active_connections > 0) entry->active_connections--;
    pthread_mutex_unlock(&ip_list_mutex);

    close(clientSock);
    printf("Conexão encerrada com %s\n", addrbuf);
    return NULL;
}

int main(int argc, const char **argv) {
    int serverPort = DEFAULT_PORT;
    const char *clients_file = DEFAULT_CLIENTS_FILE;

    if (argc >= 2) serverPort = atoi(argv[1]);
    if (argc >= 3) clients_file = argv[2];
    if (argc >= 4) server_max_kbps = atoi(argv[3]);

    load_clients_file(clients_file);
    printf("Servidor: porta=%d, clients_file=%s, server_max_kbps=%d kbps\n", serverPort, clients_file, server_max_kbps);

    int rc;
    struct sockaddr_in serverSa;
    struct sockaddr_in clientSa;
    socklen_t clientSaSize;
    int on = 1;

    int s = socket(PF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); exit(1); }
    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    (void)rc;

    memset(&serverSa, 0, sizeof(serverSa));
    serverSa.sin_family = AF_INET;
    serverSa.sin_addr.s_addr = htonl(INADDR_ANY);
    serverSa.sin_port = htons(serverPort);

    rc = bind(s, (struct sockaddr *)&serverSa, sizeof(serverSa));
    if (rc < 0) { perror("bind failed"); exit(1); }

    rc = listen(s, 50);
    if (rc < 0) { perror("listen failed"); exit(1); }

    printf("Servidor ouvindo na porta %d...\n", serverPort);

    while (1) {
        clientSaSize = sizeof(clientSa);
        int *clientSock = malloc(sizeof(int));
        if (!clientSock) { perror("malloc"); continue; }
        *clientSock = accept(s, (struct sockaddr *)&clientSa, &clientSaSize);
        if (*clientSock < 0) {
            perror("accept failed");
            free(clientSock);
            continue;
        }
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientSa.sin_addr, ipstr, sizeof(ipstr));
        printf("Cliente conectado: %s\n", ipstr);

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, clientSock) != 0) {
            perror("pthread_create");
            close(*clientSock);
            free(clientSock);
            continue;
        }
        pthread_detach(tid);
    }

    close(s);
    return 0;
}
