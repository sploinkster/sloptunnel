#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
typedef SOCKET socket_t;
#define ST_INVALID_SOCKET INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
typedef int socket_t;
#define ST_INVALID_SOCKET (-1)
#endif

#define ST_VERSION 1
#define ST_HEADER_LEN 36
#define ST_MAX_PAYLOAD 1200
#define ST_MAX_PACKET (ST_HEADER_LEN + ST_MAX_PAYLOAD)
#define ST_STREAM_BUF (ST_MAX_PACKET * 2)
#define ST_MAX_CONFIG_PORTS 256
#define ST_MAX_MENU_PATHS 16
#define ST_DEFAULT_MAX_AUTO_PORTS 65535
#define ST_SCAN_BURST 96
#define ST_TCP_SCAN_BURST 16
#define ST_MAX_TCP_PENDING 128
#define ST_MAX_TCP_CONNS 1024
#define ST_TCP_CONNECT_TIMEOUT_MS 1500
#define ST_SERVER_RECV_BUDGET 512
#define ST_MAX_MENU 8
#define ST_DEFAULT_SERVER "18.219.84.252"
#define ST_DEFAULT_TOKEN "change-me"

enum {
    PKT_HELLO = 1,
    PKT_HELLO_ACK = 2,
    PKT_DATA = 3,
    PKT_STATS = 4,
    PKT_BYE = 5
};

typedef enum {
    MODE_CLIENT = 0,
    MODE_SERVER = 1
} app_mode_t;

typedef enum {
    TRANSPORT_UDP = 1,
    TRANSPORT_TCP = 2,
    TRANSPORT_BOTH = 3
} transport_t;

typedef enum {
    PATH_UDP = 1,
    PATH_TCP = 2
} path_proto_t;

typedef enum {
    KEY_NONE = 0,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_ENTER,
    KEY_BACKSPACE,
    KEY_ESC,
    KEY_CHAR
} key_type_t;

typedef struct {
    key_type_t type;
    int ch;
} key_event_t;

typedef struct {
    app_mode_t mode;
    transport_t transport;
    char server_ip[128];
    uint16_t ports[ST_MAX_CONFIG_PORTS];
    int port_count;
    int auto_ports;
    uint16_t range_start;
    uint16_t range_end;
    int max_auto_ports;
    char token[160];
    double rate_mbps;
    int tui;
} config_t;

typedef struct {
    path_proto_t proto;
    uint16_t port;
    socket_t fd;
    struct sockaddr_in remote;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t last_tx_bytes;
    uint64_t last_rx_bytes;
    double tx_bps;
    double rx_bps;
    uint64_t last_ack_ms;
    double rtt_ms;
    int healthy;
    int shared_fd;
    uint8_t *rx_buf;
    size_t rx_len;
} path_t;

typedef struct {
    socket_t fd;
    uint16_t port;
    uint64_t started_ms;
    uint64_t hello_seq;
    int connected;
    uint8_t rx_buf[ST_STREAM_BUF];
    size_t rx_len;
} tcp_pending_t;

typedef struct {
    socket_t fd;
    int path_index;
    uint8_t rx_buf[ST_STREAM_BUF];
    size_t rx_len;
    uint64_t last_seen_ms;
} tcp_conn_t;

typedef struct {
    uint64_t seq;
    uint64_t sent_ms;
} seq_time_t;

typedef struct {
    uint64_t session;
    uint64_t last_seen_ms;
    uint64_t rx_bytes;
} peer_t;

typedef struct {
    config_t cfg;
    path_t *paths;
    int path_count;
    int path_capacity;
    socket_t shared_client_fd;
    uint16_t udp_probe_next_port;
    uint16_t tcp_probe_next_port;
    int udp_scan_complete;
    int tcp_scan_complete;
    int server_poll_cursor;
    tcp_pending_t tcp_pending[ST_MAX_TCP_PENDING];
    tcp_conn_t tcp_conns[ST_MAX_TCP_CONNS];
    int tcp_conn_count;
    uint64_t key0;
    uint64_t key1;
    uint64_t session;
    uint64_t seq;
    uint64_t started_ms;
    uint64_t last_rate_ms;
    uint64_t last_hello_ms;
    uint64_t last_draw_ms;
    uint64_t total_tx;
    uint64_t total_rx;
    double tx_bps;
    double rx_bps;
    double send_credit;
    int next_path;
    int running;
    int active_peers;
    peer_t peers[32];
    seq_time_t sent[512];
    char status[256];
} engine_t;

static volatile sig_atomic_t g_stop = 0;

#ifndef _WIN32
static struct termios g_old_termios;
static int g_old_stdin_flags = -1;
static int g_term_active = 0;
#endif

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

static uint64_t read_le64(const uint8_t *p) {
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint64_t siphash24(const uint8_t *in, size_t inlen, uint64_t k0, uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    const uint8_t *end = in + inlen - (inlen % 8);
    uint64_t b = ((uint64_t)inlen) << 56;

#define SIPROUND() do { \
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32); \
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; \
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; \
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32); \
    } while (0)

    for (; in != end; in += 8) {
        uint64_t m = read_le64(in);
        v3 ^= m;
        SIPROUND();
        SIPROUND();
        v0 ^= m;
    }

    switch (inlen & 7U) {
        case 7: b |= ((uint64_t)in[6]) << 48; /* fallthrough */
        case 6: b |= ((uint64_t)in[5]) << 40; /* fallthrough */
        case 5: b |= ((uint64_t)in[4]) << 32; /* fallthrough */
        case 4: b |= ((uint64_t)in[3]) << 24; /* fallthrough */
        case 3: b |= ((uint64_t)in[2]) << 16; /* fallthrough */
        case 2: b |= ((uint64_t)in[1]) << 8;  /* fallthrough */
        case 1: b |= ((uint64_t)in[0]);       /* fallthrough */
        case 0: break;
    }

    v3 ^= b;
    SIPROUND();
    SIPROUND();
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND();
    SIPROUND();
    SIPROUND();
    SIPROUND();

#undef SIPROUND
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t fnv1a64_seeded(const char *s, uint64_t seed) {
    uint64_t h = seed;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static void derive_key(const char *token, uint64_t *k0, uint64_t *k1) {
    *k0 = fnv1a64_seeded(token, 14695981039346656037ULL);
    *k1 = fnv1a64_seeded(token, 1099511628211ULL ^ ((uint64_t)strlen(token) << 32));
    if (*k0 == 0 && *k1 == 0) {
        *k1 = 0x9e3779b97f4a7c15ULL;
    }
}

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_u64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static uint64_t get_u64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           ((uint64_t)p[7]);
}

static uint64_t now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000U);
#endif
}

static int socket_valid(socket_t fd) {
#ifdef _WIN32
    return fd != INVALID_SOCKET;
#else
    return fd >= 0;
#endif
}

static void close_socket(socket_t fd) {
    if (!socket_valid(fd)) {
        return;
    }
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static int socket_would_block(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static int socket_in_progress(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEINPROGRESS || e == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK;
#endif
}

static int set_nonblocking(socket_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int network_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

static void network_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static uint64_t random_session_id(void) {
    uint64_t t = (uint64_t)time(NULL) ^ (now_ms() << 21);
#ifdef _WIN32
    t ^= (uint64_t)GetCurrentProcessId() << 32;
#else
    t ^= (uint64_t)getpid() << 32;
#endif
    t ^= fnv1a64_seeded("sloptunnel", 14695981039346656037ULL);
    return t ? t : 1;
}

static int parse_ports(const char *text, uint16_t *ports, int *count) {
    char tmp[256];
    char *tok;
    int n = 0;
    size_t len;

    if (!text || !*text) {
        return -1;
    }

    len = strlen(text);
    if (len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, text, len + 1);

    tok = strtok(tmp, ", ");
    while (tok) {
        char *end = NULL;
        long v = strtol(tok, &end, 10);
        if (!end || *end != '\0' || v < 1 || v > 65535 || n >= ST_MAX_CONFIG_PORTS) {
            return -1;
        }
        ports[n++] = (uint16_t)v;
        tok = strtok(NULL, ", ");
    }

    if (n == 0) {
        return -1;
    }
    *count = n;
    return 0;
}

static int parse_range(const char *text, uint16_t *start, uint16_t *end) {
    char *dash;
    char tmp[64];
    char *num_end = NULL;
    long a;
    long b;
    size_t len;

    if (!text || !*text) {
        return -1;
    }
    len = strlen(text);
    if (len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, text, len + 1);

    dash = strchr(tmp, '-');
    if (!dash) {
        a = strtol(tmp, &num_end, 10);
        if (!num_end || *num_end != '\0' || a < 1 || a > 65535) {
            return -1;
        }
        *start = (uint16_t)a;
        *end = (uint16_t)a;
        return 0;
    }

    *dash = '\0';
    a = strtol(tmp, &num_end, 10);
    if (!num_end || *num_end != '\0') {
        return -1;
    }
    b = strtol(dash + 1, &num_end, 10);
    if (!num_end || *num_end != '\0' || a < 1 || a > 65535 || b < 1 || b > 65535 || a > b) {
        return -1;
    }
    *start = (uint16_t)a;
    *end = (uint16_t)b;
    return 0;
}

static int parse_port_setting(const char *text, config_t *cfg) {
    const char *range = NULL;
    uint16_t start = 1;
    uint16_t end = 65535;

    if (!text || !*text) {
        return -1;
    }
    if (strcmp(text, "auto") == 0 || strcmp(text, "any") == 0) {
        cfg->auto_ports = 1;
        cfg->range_start = 1;
        cfg->range_end = 65535;
        cfg->port_count = 0;
        return 0;
    }
    if (strncmp(text, "auto:", 5) == 0) {
        range = text + 5;
    } else if (strncmp(text, "any:", 4) == 0) {
        range = text + 4;
    }
    if (range) {
        if (parse_range(range, &start, &end) != 0) {
            return -1;
        }
        cfg->auto_ports = 1;
        cfg->range_start = start;
        cfg->range_end = end;
        cfg->port_count = 0;
        return 0;
    }
    if (parse_ports(text, cfg->ports, &cfg->port_count) != 0) {
        return -1;
    }
    cfg->auto_ports = 0;
    return 0;
}

static int parse_transport(const char *text, transport_t *transport) {
    if (!text) {
        return -1;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = TRANSPORT_UDP;
        return 0;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = TRANSPORT_TCP;
        return 0;
    }
    if (strcmp(text, "both") == 0 || strcmp(text, "all") == 0) {
        *transport = TRANSPORT_BOTH;
        return 0;
    }
    return -1;
}

static int transport_has_udp(transport_t transport) {
    return transport == TRANSPORT_UDP || transport == TRANSPORT_BOTH;
}

static int transport_has_tcp(transport_t transport) {
    return transport == TRANSPORT_TCP || transport == TRANSPORT_BOTH;
}

static const char *transport_name(transport_t transport) {
    if (transport == TRANSPORT_TCP) {
        return "tcp";
    }
    if (transport == TRANSPORT_BOTH) {
        return "both";
    }
    return "udp";
}

static const char *proto_name(path_proto_t proto) {
    return proto == PATH_TCP ? "tcp" : "udp";
}

static void copy_text(char *dst, size_t dst_len, const char *src);

static void ports_to_string(const config_t *cfg, char *out, size_t out_len) {
    size_t used = 0;
    int i;
    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (cfg->auto_ports) {
        snprintf(out, out_len, "auto:%u-%u max=%d",
                 (unsigned)cfg->range_start, (unsigned)cfg->range_end,
                 cfg->max_auto_ports);
        return;
    }
    for (i = 0; i < cfg->port_count; i++) {
        int n = snprintf(out + used, out_len - used, "%s%u",
                         i ? "," : "", (unsigned)cfg->ports[i]);
        if (n < 0 || (size_t)n >= out_len - used) {
            out[out_len - 1] = '\0';
            return;
        }
        used += (size_t)n;
    }
}

static void config_defaults(config_t *cfg) {
    const char *env_token;
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = MODE_CLIENT;
    cfg->transport = TRANSPORT_BOTH;
    snprintf(cfg->server_ip, sizeof(cfg->server_ip), "%s", ST_DEFAULT_SERVER);
    snprintf(cfg->token, sizeof(cfg->token), "%s", ST_DEFAULT_TOKEN);
    env_token = getenv("SLOPTUNNEL_TOKEN");
    if (env_token && *env_token) {
        copy_text(cfg->token, sizeof(cfg->token), env_token);
    }
    cfg->rate_mbps = 4.0;
    cfg->tui = 1;
    cfg->auto_ports = 1;
    cfg->range_start = 1;
    cfg->range_end = 65535;
    cfg->max_auto_ports = ST_DEFAULT_MAX_AUTO_PORTS;
    cfg->port_count = 0;
}

static void set_status(engine_t *e, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->status, sizeof(e->status), fmt, ap);
    va_end(ap);
}

static void copy_text(char *dst, size_t dst_len, const char *src) {
    size_t n;
    if (dst_len == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= dst_len) {
        n = dst_len - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int load_token_file(config_t *cfg, const char *path) {
    FILE *f;
    char buf[256];
    size_t n;
    f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = '\0';
    }
    if (n == 0) {
        return -1;
    }
    copy_text(cfg->token, sizeof(cfg->token), buf);
    return 0;
}

static size_t build_packet(uint8_t *out, uint8_t type, uint8_t port_index,
                           uint64_t session, uint64_t seq,
                           const uint8_t *payload, uint16_t payload_len,
                           uint64_t key0, uint64_t key1) {
    uint64_t tag;
    size_t total = ST_HEADER_LEN + payload_len;
    memset(out, 0, ST_HEADER_LEN);
    out[0] = 'S';
    out[1] = 'L';
    out[2] = 'O';
    out[3] = 'T';
    out[4] = ST_VERSION;
    out[5] = type;
    out[6] = 0;
    out[7] = port_index;
    put_u64(out + 8, session);
    put_u64(out + 16, seq);
    put_u16(out + 24, payload_len);
    put_u16(out + 26, 0);
    if (payload_len && payload) {
        memcpy(out + ST_HEADER_LEN, payload, payload_len);
    }
    tag = siphash24(out, total, key0, key1);
    put_u64(out + 28, tag);
    return total;
}

static int verify_packet(uint8_t *buf, size_t len, uint64_t key0, uint64_t key1,
                         uint8_t *type, uint8_t *port_index,
                         uint64_t *session, uint64_t *seq,
                         uint8_t **payload, uint16_t *payload_len) {
    uint64_t seen;
    uint64_t calc;

    if (len < ST_HEADER_LEN || buf[0] != 'S' || buf[1] != 'L' ||
        buf[2] != 'O' || buf[3] != 'T' || buf[4] != ST_VERSION) {
        return -1;
    }

    *payload_len = get_u16(buf + 24);
    if (ST_HEADER_LEN + (size_t)*payload_len != len || *payload_len > ST_MAX_PAYLOAD) {
        return -1;
    }

    seen = get_u64(buf + 28);
    memset(buf + 28, 0, 8);
    calc = siphash24(buf, len, key0, key1);
    put_u64(buf + 28, seen);
    if (calc != seen) {
        return -1;
    }

    *type = buf[5];
    *port_index = buf[7];
    *session = get_u64(buf + 8);
    *seq = get_u64(buf + 16);
    *payload = buf + ST_HEADER_LEN;
    return 0;
}

static int make_udp_socket(uint16_t port, int bind_any, const char *remote_ip,
                           socket_t *fd, struct sockaddr_in *remote) {
    socket_t s;
    int yes = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (!socket_valid(s)) {
        return -1;
    }

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    if (set_nonblocking(s) != 0) {
        close_socket(s);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (bind_any) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close_socket(s);
            return -1;
        }
    } else {
        if (!remote_ip || inet_pton(AF_INET, remote_ip, &addr.sin_addr) != 1) {
            close_socket(s);
            return -1;
        }
        if (remote) {
            *remote = addr;
        }
    }

    *fd = s;
    return 0;
}

static int fill_remote_addr(const char *remote_ip, uint16_t port, struct sockaddr_in *remote);

static int make_tcp_listener(uint16_t port, socket_t *fd) {
    socket_t s;
    int yes = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!socket_valid(s)) {
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    if (set_nonblocking(s) != 0) {
        close_socket(s);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close_socket(s);
        return -1;
    }
    if (listen(s, 64) != 0) {
        close_socket(s);
        return -1;
    }
    *fd = s;
    return 0;
}

static int make_tcp_connect_socket(const char *remote_ip, uint16_t port,
                                   socket_t *fd, int *connected) {
    socket_t s;
    struct sockaddr_in remote;

    if (fill_remote_addr(remote_ip, port, &remote) != 0) {
        return -1;
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!socket_valid(s)) {
        return -1;
    }
    if (set_nonblocking(s) != 0) {
        close_socket(s);
        return -1;
    }

    if (connect(s, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
        *fd = s;
        *connected = 1;
        return 0;
    }
    if (socket_in_progress()) {
        *fd = s;
        *connected = 0;
        return 0;
    }
    close_socket(s);
    return -1;
}

static int make_unbound_udp_socket(socket_t *fd) {
    socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (!socket_valid(s)) {
        return -1;
    }
    if (set_nonblocking(s) != 0) {
        close_socket(s);
        return -1;
    }
    *fd = s;
    return 0;
}

static int fill_remote_addr(const char *remote_ip, uint16_t port, struct sockaddr_in *remote) {
    memset(remote, 0, sizeof(*remote));
    remote->sin_family = AF_INET;
    remote->sin_port = htons(port);
    return inet_pton(AF_INET, remote_ip, &remote->sin_addr) == 1 ? 0 : -1;
}

static int range_size(const config_t *cfg) {
    return (int)((unsigned)cfg->range_end - (unsigned)cfg->range_start + 1U);
}

static int auto_capacity(const config_t *cfg) {
    int n = range_size(cfg);
    if (cfg->max_auto_ports > 0 && cfg->max_auto_ports < n) {
        n = cfg->max_auto_ports;
    }
    return n > 0 ? n : 1;
}

static int transport_count(transport_t transport) {
    return transport == TRANSPORT_BOTH ? 2 : 1;
}

static path_t *find_path(engine_t *e, path_proto_t proto, uint16_t port) {
    int i;
    for (i = 0; i < e->path_count; i++) {
        if (e->paths[i].proto == proto && e->paths[i].port == port) {
            return &e->paths[i];
        }
    }
    return NULL;
}

static path_t *add_path(engine_t *e, path_proto_t proto, uint16_t port) {
    path_t *p;
    if (e->path_count >= e->path_capacity) {
        return NULL;
    }
    p = &e->paths[e->path_count++];
    memset(p, 0, sizeof(*p));
    p->proto = proto;
    p->port = port;
    p->fd = ST_INVALID_SOCKET;
    p->healthy = 1;
    return p;
}

static void remember_sent(engine_t *e, uint64_t seq, uint64_t t_ms) {
    e->sent[seq % (sizeof(e->sent) / sizeof(e->sent[0]))].seq = seq;
    e->sent[seq % (sizeof(e->sent) / sizeof(e->sent[0]))].sent_ms = t_ms;
}

static int find_sent(engine_t *e, uint64_t seq, uint64_t *sent_ms) {
    seq_time_t *slot = &e->sent[seq % (sizeof(e->sent) / sizeof(e->sent[0]))];
    if (slot->seq == seq && slot->sent_ms != 0) {
        *sent_ms = slot->sent_ms;
        return 0;
    }
    return -1;
}

static void mark_peer(engine_t *e, uint64_t session, uint64_t now, size_t bytes) {
    int empty = -1;
    int i;
    for (i = 0; i < (int)(sizeof(e->peers) / sizeof(e->peers[0])); i++) {
        if (e->peers[i].session == session) {
            e->peers[i].last_seen_ms = now;
            e->peers[i].rx_bytes += bytes;
            return;
        }
        if (empty < 0 && e->peers[i].session == 0) {
            empty = i;
        }
    }
    if (empty >= 0) {
        e->peers[empty].session = session;
        e->peers[empty].last_seen_ms = now;
        e->peers[empty].rx_bytes = bytes;
    }
}

static int count_active_peers(engine_t *e, uint64_t now) {
    int n = 0;
    int i;
    for (i = 0; i < (int)(sizeof(e->peers) / sizeof(e->peers[0])); i++) {
        if (e->peers[i].session != 0 && now - e->peers[i].last_seen_ms < 10000) {
            n++;
        }
    }
    return n;
}

static int send_all_now(socket_t fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int sent = (int)send(fd, (const char *)buf + off, (int)(len - off), 0);
        if (sent > 0) {
            off += (size_t)sent;
            continue;
        }
        if (sent < 0 && socket_would_block()) {
            break;
        }
        return -1;
    }
    return (int)off;
}

static int send_packet_fd(engine_t *e, socket_t fd, uint8_t type, uint8_t port_index,
                          uint64_t seq, const uint8_t *payload, uint16_t payload_len) {
    uint8_t packet[ST_MAX_PACKET];
    size_t len = build_packet(packet, type, port_index, e->session, seq, payload,
                              payload_len, e->key0, e->key1);
    return send_all_now(fd, packet, len);
}

static int send_packet_path(engine_t *e, path_t *p, uint8_t type, uint8_t port_index,
                            uint64_t seq, const uint8_t *payload, uint16_t payload_len,
                            const struct sockaddr_in *to) {
    uint8_t packet[ST_MAX_PACKET];
    size_t len = build_packet(packet, type, port_index, e->session, seq, payload,
                              payload_len, e->key0, e->key1);
    int sent;
    const struct sockaddr_in *dst = to ? to : &p->remote;

    if (p->proto == PATH_TCP) {
        sent = send_all_now(p->fd, packet, len);
    } else {
        sent = (int)sendto(p->fd, (const char *)packet, (int)len, 0,
                           (const struct sockaddr *)dst, sizeof(*dst));
    }
    if (sent < 0) {
        if (socket_would_block()) {
            return 0;
        }
        return -1;
    }
    p->tx_bytes += (uint64_t)sent;
    p->tx_packets++;
    e->total_tx += (uint64_t)sent;
    return sent;
}

static int tcp_pending_exists(engine_t *e, uint16_t port) {
    int i;
    for (i = 0; i < ST_MAX_TCP_PENDING; i++) {
        if (socket_valid(e->tcp_pending[i].fd) && e->tcp_pending[i].port == port) {
            return 1;
        }
    }
    return 0;
}

static void clear_tcp_pending(tcp_pending_t *p, int close_fd) {
    if (close_fd) {
        close_socket(p->fd);
    }
    memset(p, 0, sizeof(*p));
    p->fd = ST_INVALID_SOCKET;
}

static int tcp_socket_ready(socket_t fd) {
    fd_set wfds;
    struct timeval tv;
    int rc;
    int err = 0;
#ifdef _WIN32
    int err_len = sizeof(err);
#else
    socklen_t err_len = sizeof(err);
    if (fd >= FD_SETSIZE) {
        return 0;
    }
#endif

    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select((int)fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0 || !FD_ISSET(fd, &wfds)) {
        return 0;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &err_len) != 0) {
        return -1;
    }
    return err == 0 ? 1 : -1;
}

static int add_tcp_pending(engine_t *e, socket_t fd, uint16_t port,
                           int connected, uint64_t now) {
    int i;
    for (i = 0; i < ST_MAX_TCP_PENDING; i++) {
        if (!socket_valid(e->tcp_pending[i].fd)) {
            tcp_pending_t *p = &e->tcp_pending[i];
            memset(p, 0, sizeof(*p));
            p->fd = fd;
            p->port = port;
            p->started_ms = now;
            p->connected = connected;
            if (connected) {
                p->hello_seq = e->seq++;
                send_packet_fd(e, fd, PKT_HELLO, 0, p->hello_seq, NULL, 0);
                remember_sent(e, p->hello_seq, now);
            }
            return 0;
        }
    }
    close_socket(fd);
    return -1;
}

static int start_tcp_probe_port(engine_t *e, uint16_t port, uint64_t now) {
    socket_t fd = ST_INVALID_SOCKET;
    int connected = 0;
    if (find_path(e, PATH_TCP, port) || tcp_pending_exists(e, port)) {
        return 0;
    }
    if (make_tcp_connect_socket(e->cfg.server_ip, port, &fd, &connected) != 0) {
        return -1;
    }
    return add_tcp_pending(e, fd, port, connected, now);
}

static int validate_tcp_pending(engine_t *e, tcp_pending_t *tp, uint64_t now) {
    for (;;) {
        int got;
        got = (int)recv(tp->fd, (char *)tp->rx_buf + tp->rx_len,
                        (int)(sizeof(tp->rx_buf) - tp->rx_len), 0);
        if (got == 0) {
            return -1;
        }
        if (got < 0) {
            if (socket_would_block()) {
                return 0;
            }
            return -1;
        }
        tp->rx_len += (size_t)got;
        while (tp->rx_len >= ST_HEADER_LEN) {
            uint16_t payload_len = get_u16(tp->rx_buf + 24);
            size_t packet_len = ST_HEADER_LEN + (size_t)payload_len;
            uint8_t type = 0;
            uint8_t port_index = 0;
            uint64_t session = 0;
            uint64_t seq = 0;
            uint8_t *payload = NULL;
            path_t *path;
            if (payload_len > ST_MAX_PAYLOAD || packet_len > sizeof(tp->rx_buf)) {
                return -1;
            }
            if (tp->rx_len < packet_len) {
                break;
            }
            if (verify_packet(tp->rx_buf, packet_len, e->key0, e->key1, &type, &port_index,
                              &session, &seq, &payload, &payload_len) != 0) {
                return -1;
            }
            (void)port_index;
            (void)session;
            (void)payload;
            if (type == PKT_HELLO_ACK && seq == tp->hello_seq) {
                path = add_path(e, PATH_TCP, tp->port);
                if (!path) {
                    return -1;
                }
                path->fd = tp->fd;
                path->healthy = 1;
                fill_remote_addr(e->cfg.server_ip, tp->port, &path->remote);
                path->last_ack_ms = now;
                path->rx_bytes += packet_len;
                path->rx_packets++;
                e->total_rx += packet_len;
                set_status(e, "Discovered authenticated TCP path on port %u",
                           (unsigned)tp->port);
                tp->fd = ST_INVALID_SOCKET;
                return 1;
            }
            memmove(tp->rx_buf, tp->rx_buf + packet_len, tp->rx_len - packet_len);
            tp->rx_len -= packet_len;
        }
    }
}

static void complete_tcp_pending(engine_t *e, uint64_t now) {
    int i;
    for (i = 0; i < ST_MAX_TCP_PENDING; i++) {
        tcp_pending_t *tp = &e->tcp_pending[i];
        int state;
        if (!socket_valid(tp->fd)) {
            continue;
        }
        if (!tp->connected) {
            state = tcp_socket_ready(tp->fd);
            if (state < 0) {
                clear_tcp_pending(tp, 1);
                continue;
            }
            if (state > 0) {
                tp->connected = 1;
                tp->hello_seq = e->seq++;
                send_packet_fd(e, tp->fd, PKT_HELLO, 0, tp->hello_seq, NULL, 0);
                remember_sent(e, tp->hello_seq, now);
            }
        } else {
            state = validate_tcp_pending(e, tp, now);
            if (state < 0) {
                clear_tcp_pending(tp, 1);
                continue;
            }
            if (state > 0) {
                clear_tcp_pending(tp, 0);
                continue;
            }
        }
        if (now - tp->started_ms > ST_TCP_CONNECT_TIMEOUT_MS) {
            clear_tcp_pending(tp, 1);
        }
    }
}

static void engine_stop(engine_t *e);

static int engine_start(engine_t *e) {
    int i;
    int capacity;
    uint64_t now;
    free(e->paths);
    e->paths = NULL;
    memset(e->peers, 0, sizeof(e->peers));
    memset(e->sent, 0, sizeof(e->sent));
    memset(e->tcp_pending, 0, sizeof(e->tcp_pending));
    memset(e->tcp_conns, 0, sizeof(e->tcp_conns));
    for (i = 0; i < ST_MAX_TCP_PENDING; i++) {
        e->tcp_pending[i].fd = ST_INVALID_SOCKET;
    }
    for (i = 0; i < ST_MAX_TCP_CONNS; i++) {
        e->tcp_conns[i].fd = ST_INVALID_SOCKET;
    }
    e->tcp_conn_count = 0;
    e->path_count = 0;
    e->path_capacity = 0;
    e->shared_client_fd = ST_INVALID_SOCKET;
    e->udp_probe_next_port = e->cfg.range_start;
    e->tcp_probe_next_port = e->cfg.range_start;
    e->udp_scan_complete = 0;
    e->tcp_scan_complete = 0;
    e->server_poll_cursor = 0;
    e->session = random_session_id();
    e->seq = 1;
    now = now_ms();
    e->started_ms = now;
    e->last_rate_ms = e->started_ms;
    e->last_hello_ms = 0;
    e->send_credit = 0.0;
    e->next_path = 0;
    e->total_tx = 0;
    e->total_rx = 0;
    e->tx_bps = 0.0;
    e->rx_bps = 0.0;
    derive_key(e->cfg.token, &e->key0, &e->key1);

    capacity = e->cfg.auto_ports ? auto_capacity(&e->cfg) : e->cfg.port_count;
    capacity *= transport_count(e->cfg.transport);
    if (capacity <= 0) {
        set_status(e, "No ports configured");
        return -1;
    }
    e->paths = (path_t *)calloc((size_t)capacity, sizeof(path_t));
    if (!e->paths) {
        set_status(e, "Out of memory allocating paths");
        return -1;
    }
    e->path_capacity = capacity;

    if (e->cfg.auto_ports && e->cfg.mode == MODE_SERVER) {
        uint32_t port;
        for (port = e->cfg.range_start; port <= (uint32_t)e->cfg.range_end; port++) {
            if (e->path_count >= e->path_capacity) {
                break;
            }
            if (transport_has_tcp(e->cfg.transport)) {
                path_t *p = add_path(e, PATH_TCP, (uint16_t)port);
                if (!p) {
                    break;
                }
                if (make_tcp_listener(p->port, &p->fd) != 0) {
                    e->path_count--;
                }
            }
            if (e->path_count >= e->path_capacity) {
                break;
            }
            if (transport_has_udp(e->cfg.transport)) {
                path_t *p = add_path(e, PATH_UDP, (uint16_t)port);
                if (!p) {
                    break;
                }
                if (make_udp_socket(p->port, 1, NULL, &p->fd, NULL) != 0) {
                    e->path_count--;
                }
            }
        }
        if (e->path_count == 0) {
            set_status(e, "No %s ports could be bound in %u-%u",
                       transport_name(e->cfg.transport),
                       (unsigned)e->cfg.range_start, (unsigned)e->cfg.range_end);
            engine_stop(e);
            return -1;
        }
    } else if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        if (transport_has_udp(e->cfg.transport) &&
            make_unbound_udp_socket(&e->shared_client_fd) != 0) {
            set_status(e, "Could not create UDP probe socket");
            engine_stop(e);
            return -1;
        }
    } else {
        for (i = 0; i < e->cfg.port_count; i++) {
            if (e->cfg.mode == MODE_SERVER) {
                if (transport_has_tcp(e->cfg.transport)) {
                    path_t *p = add_path(e, PATH_TCP, e->cfg.ports[i]);
                    if (!p || make_tcp_listener(p->port, &p->fd) != 0) {
                        if (p) {
                            e->path_count--;
                        }
                        set_status(e, "Could not bind TCP port %u", (unsigned)e->cfg.ports[i]);
                        engine_stop(e);
                        return -1;
                    }
                }
                if (transport_has_udp(e->cfg.transport)) {
                    path_t *p = add_path(e, PATH_UDP, e->cfg.ports[i]);
                    if (!p || make_udp_socket(p->port, 1, NULL, &p->fd, NULL) != 0) {
                        if (p) {
                            e->path_count--;
                        }
                        set_status(e, "Could not bind UDP port %u", (unsigned)e->cfg.ports[i]);
                        engine_stop(e);
                        return -1;
                    }
                }
            } else {
                if (transport_has_udp(e->cfg.transport)) {
                    path_t *p = add_path(e, PATH_UDP, e->cfg.ports[i]);
                    if (!p || make_udp_socket(p->port, 0, e->cfg.server_ip, &p->fd, &p->remote) != 0) {
                        if (p) {
                            e->path_count--;
                        }
                        set_status(e, "Invalid server IP or UDP socket failure for %s:%u",
                                   e->cfg.server_ip, (unsigned)e->cfg.ports[i]);
                        engine_stop(e);
                        return -1;
                    }
                }
                if (transport_has_tcp(e->cfg.transport)) {
                    start_tcp_probe_port(e, e->cfg.ports[i], now);
                }
            }
        }
        if (e->cfg.mode == MODE_SERVER && e->path_count == 0) {
            set_status(e, "No paths available");
            engine_stop(e);
            return -1;
        }
    }

    if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        struct sockaddr_in probe;
        if (fill_remote_addr(e->cfg.server_ip, e->cfg.range_start, &probe) != 0) {
            set_status(e, "Invalid server IP: %s", e->cfg.server_ip);
            engine_stop(e);
            return -1;
        }
    } else if (e->cfg.mode == MODE_CLIENT) {
        for (i = 0; i < e->path_count; i++) {
            if (fill_remote_addr(e->cfg.server_ip, e->paths[i].port, &e->paths[i].remote) != 0) {
                set_status(e, "Invalid server IP or socket failure for %s:%u",
                           e->cfg.server_ip, (unsigned)e->paths[i].port);
                engine_stop(e);
                return -1;
            }
        }
    }

    e->running = 1;
    if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        set_status(e, "Client probing %s ports %u-%u with %d path slots",
                   transport_name(e->cfg.transport),
                   (unsigned)e->cfg.range_start, (unsigned)e->cfg.range_end,
                   e->path_capacity);
    } else {
        set_status(e, "%s started with %d %s path%s",
                   e->cfg.mode == MODE_SERVER ? "Server" : "Client",
                   e->path_count, transport_name(e->cfg.transport),
                   e->path_count == 1 ? "" : "s");
    }
    return 0;
}

static void engine_stop(engine_t *e) {
    int i;
    for (i = 0; i < ST_MAX_TCP_PENDING; i++) {
        clear_tcp_pending(&e->tcp_pending[i], 1);
    }
    for (i = 0; i < ST_MAX_TCP_CONNS; i++) {
        close_socket(e->tcp_conns[i].fd);
        e->tcp_conns[i].fd = ST_INVALID_SOCKET;
    }
    e->tcp_conn_count = 0;
    for (i = 0; i < e->path_count; i++) {
        if (!e->paths[i].shared_fd) {
            close_socket(e->paths[i].fd);
        }
        free(e->paths[i].rx_buf);
        e->paths[i].rx_buf = NULL;
        e->paths[i].fd = ST_INVALID_SOCKET;
    }
    close_socket(e->shared_client_fd);
    e->shared_client_fd = ST_INVALID_SOCKET;
    free(e->paths);
    e->paths = NULL;
    e->path_count = 0;
    e->path_capacity = 0;
    e->running = 0;
    set_status(e, "Stopped");
}

static void update_rates(engine_t *e, uint64_t now) {
    uint64_t elapsed = now - e->last_rate_ms;
    uint64_t tx_delta = 0;
    uint64_t rx_delta = 0;
    int i;
    if (elapsed < 1000) {
        return;
    }
    for (i = 0; i < e->path_count; i++) {
        path_t *p = &e->paths[i];
        uint64_t ptx = p->tx_bytes - p->last_tx_bytes;
        uint64_t prx = p->rx_bytes - p->last_rx_bytes;
        p->tx_bps = ((double)ptx * 1000.0) / (double)elapsed;
        p->rx_bps = ((double)prx * 1000.0) / (double)elapsed;
        p->last_tx_bytes = p->tx_bytes;
        p->last_rx_bytes = p->rx_bytes;
        p->healthy = (e->cfg.mode == MODE_SERVER) || p->last_ack_ms == 0 ||
                     (now - p->last_ack_ms < 5000);
        tx_delta += ptx;
        rx_delta += prx;
    }
    e->tx_bps = ((double)tx_delta * 1000.0) / (double)elapsed;
    e->rx_bps = ((double)rx_delta * 1000.0) / (double)elapsed;
    e->active_peers = count_active_peers(e, now);
    e->last_rate_ms = now;
}

static void receive_server(engine_t *e, path_t *p, int index, uint64_t now) {
    uint8_t buf[ST_MAX_PACKET];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    for (;;) {
        int got;
        uint8_t type = 0;
        uint8_t port_index = 0;
        uint64_t session = 0;
        uint64_t seq = 0;
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;

        got = (int)recvfrom(p->fd, (char *)buf, sizeof(buf), 0,
                            (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (!socket_would_block()) {
                set_status(e, "Server recv error on port %u", (unsigned)p->port);
            }
            break;
        }

        if (verify_packet(buf, (size_t)got, e->key0, e->key1, &type, &port_index,
                          &session, &seq, &payload, &payload_len) != 0) {
            continue;
        }

        (void)payload;
        p->rx_bytes += (uint64_t)got;
        p->rx_packets++;
        e->total_rx += (uint64_t)got;
        mark_peer(e, session, now, (size_t)got);

        if (type == PKT_HELLO) {
            send_packet_path(e, p, PKT_HELLO_ACK, (uint8_t)index, seq, NULL, 0, &from);
        } else if (type == PKT_DATA || type == PKT_STATS) {
            send_packet_path(e, p, PKT_STATS, (uint8_t)index, seq, NULL, 0, &from);
        } else if (type == PKT_BYE) {
            set_status(e, "Client session %" PRIu64 " closed", session);
        }
    }
}

static void remove_tcp_conn(engine_t *e, int index) {
    if (index < 0 || index >= e->tcp_conn_count) {
        return;
    }
    close_socket(e->tcp_conns[index].fd);
    e->tcp_conns[index].fd = ST_INVALID_SOCKET;
    if (index != e->tcp_conn_count - 1) {
        e->tcp_conns[index] = e->tcp_conns[e->tcp_conn_count - 1];
    }
    memset(&e->tcp_conns[e->tcp_conn_count - 1], 0, sizeof(e->tcp_conns[0]));
    e->tcp_conns[e->tcp_conn_count - 1].fd = ST_INVALID_SOCKET;
    e->tcp_conn_count--;
}

static int add_tcp_conn(engine_t *e, socket_t fd, int path_index, uint64_t now) {
    tcp_conn_t *c;
    if (e->tcp_conn_count >= ST_MAX_TCP_CONNS) {
        close_socket(fd);
        return -1;
    }
    c = &e->tcp_conns[e->tcp_conn_count++];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->path_index = path_index;
    c->last_seen_ms = now;
    return 0;
}

static void accept_tcp_server(engine_t *e, path_t *p, int index, uint64_t now) {
    for (;;) {
        struct sockaddr_in from;
#ifdef _WIN32
        int from_len = sizeof(from);
#else
        socklen_t from_len = sizeof(from);
#endif
        socket_t fd = accept(p->fd, (struct sockaddr *)&from, &from_len);
        if (!socket_valid(fd)) {
            if (!socket_would_block()) {
                set_status(e, "TCP accept error on port %u", (unsigned)p->port);
            }
            break;
        }
        set_nonblocking(fd);
        if (add_tcp_conn(e, fd, index, now) != 0) {
            set_status(e, "TCP connection limit reached");
            break;
        }
    }
}

static int handle_server_tcp_packet(engine_t *e, tcp_conn_t *c,
                                    const uint8_t *packet, size_t packet_len,
                                    uint64_t now) {
    uint8_t tmp[ST_MAX_PACKET];
    uint8_t type = 0;
    uint8_t port_index = 0;
    uint64_t session = 0;
    uint64_t seq = 0;
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;
    path_t *p;
    uint8_t reply_type;
    int sent;

    if (c->path_index < 0 || c->path_index >= e->path_count) {
        return -1;
    }
    p = &e->paths[c->path_index];
    if (packet_len > sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, packet, packet_len);
    if (verify_packet(tmp, packet_len, e->key0, e->key1, &type, &port_index,
                      &session, &seq, &payload, &payload_len) != 0) {
        return -1;
    }
    (void)port_index;
    (void)payload;
    (void)payload_len;

    p->rx_bytes += packet_len;
    p->rx_packets++;
    e->total_rx += packet_len;
    c->last_seen_ms = now;
    mark_peer(e, session, now, packet_len);

    if (type == PKT_BYE) {
        set_status(e, "TCP client session %" PRIu64 " closed", session);
        return -1;
    }
    reply_type = type == PKT_HELLO ? PKT_HELLO_ACK : PKT_STATS;
    sent = send_packet_fd(e, c->fd, reply_type, (uint8_t)c->path_index, seq, NULL, 0);
    if (sent > 0) {
        p->tx_bytes += (uint64_t)sent;
        p->tx_packets++;
        e->total_tx += (uint64_t)sent;
    }
    return 0;
}

static void receive_tcp_connections(engine_t *e, uint64_t now) {
    int i = 0;
    while (i < e->tcp_conn_count) {
        tcp_conn_t *c = &e->tcp_conns[i];
        int remove_conn = 0;
        for (;;) {
            int got = (int)recv(c->fd, (char *)c->rx_buf + c->rx_len,
                                (int)(sizeof(c->rx_buf) - c->rx_len), 0);
            if (got == 0) {
                remove_conn = 1;
                break;
            }
            if (got < 0) {
                if (!socket_would_block()) {
                    remove_conn = 1;
                }
                break;
            }
            c->rx_len += (size_t)got;
            while (c->rx_len >= ST_HEADER_LEN) {
                uint16_t payload_len = get_u16(c->rx_buf + 24);
                size_t packet_len = ST_HEADER_LEN + (size_t)payload_len;
                if (payload_len > ST_MAX_PAYLOAD || packet_len > sizeof(c->rx_buf)) {
                    remove_conn = 1;
                    break;
                }
                if (c->rx_len < packet_len) {
                    break;
                }
                if (handle_server_tcp_packet(e, c, c->rx_buf, packet_len, now) != 0) {
                    remove_conn = 1;
                    break;
                }
                memmove(c->rx_buf, c->rx_buf + packet_len, c->rx_len - packet_len);
                c->rx_len -= packet_len;
            }
            if (remove_conn || c->rx_len == sizeof(c->rx_buf)) {
                remove_conn = 1;
                break;
            }
        }
        if (remove_conn || now - c->last_seen_ms > 30000) {
            remove_tcp_conn(e, i);
            continue;
        }
        i++;
    }
}

static void receive_client(engine_t *e, path_t *p, uint64_t now) {
    uint8_t buf[ST_MAX_PACKET];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    for (;;) {
        int got;
        uint8_t type = 0;
        uint8_t port_index = 0;
        uint64_t session = 0;
        uint64_t seq = 0;
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint64_t sent_ms = 0;

        got = (int)recvfrom(p->fd, (char *)buf, sizeof(buf), 0,
                            (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (!socket_would_block()) {
                set_status(e, "Client recv error on port %u", (unsigned)p->port);
            }
            break;
        }

        if (verify_packet(buf, (size_t)got, e->key0, e->key1, &type, &port_index,
                          &session, &seq, &payload, &payload_len) != 0) {
            continue;
        }
        (void)session;
        (void)payload;
        (void)payload_len;
        (void)port_index;

        p->rx_bytes += (uint64_t)got;
        p->rx_packets++;
        e->total_rx += (uint64_t)got;
        p->last_ack_ms = now;
        p->healthy = 1;

        if ((type == PKT_STATS || type == PKT_HELLO_ACK) && find_sent(e, seq, &sent_ms) == 0) {
            p->rtt_ms = (double)(now - sent_ms);
        }
    }
}

static void receive_client_tcp(engine_t *e, path_t *p, uint64_t now) {
    if (!p->rx_buf) {
        p->rx_buf = (uint8_t *)malloc(ST_STREAM_BUF);
        if (!p->rx_buf) {
            p->healthy = 0;
            set_status(e, "Out of memory for TCP receive buffer");
            return;
        }
        p->rx_len = 0;
    }
    for (;;) {
        int got;
        got = (int)recv(p->fd, (char *)p->rx_buf + p->rx_len,
                        (int)(ST_STREAM_BUF - p->rx_len), 0);
        if (got == 0) {
            p->healthy = 0;
            close_socket(p->fd);
            p->fd = ST_INVALID_SOCKET;
            set_status(e, "TCP path closed on port %u", (unsigned)p->port);
            return;
        }
        if (got < 0) {
            if (!socket_would_block()) {
                p->healthy = 0;
                close_socket(p->fd);
                p->fd = ST_INVALID_SOCKET;
                set_status(e, "TCP recv error on port %u", (unsigned)p->port);
            }
            return;
        }
        p->rx_len += (size_t)got;
        while (p->rx_len >= ST_HEADER_LEN) {
            uint16_t payload_len = get_u16(p->rx_buf + 24);
            size_t packet_len = ST_HEADER_LEN + (size_t)payload_len;
            uint8_t type = 0;
            uint8_t port_index = 0;
            uint64_t session = 0;
            uint64_t seq = 0;
            uint8_t *payload = NULL;
            uint64_t sent_ms = 0;
            if (payload_len > ST_MAX_PAYLOAD || packet_len > ST_STREAM_BUF) {
                p->healthy = 0;
                close_socket(p->fd);
                p->fd = ST_INVALID_SOCKET;
                return;
            }
            if (p->rx_len < packet_len) {
                break;
            }
            if (verify_packet(p->rx_buf, packet_len, e->key0, e->key1, &type, &port_index,
                              &session, &seq, &payload, &payload_len) != 0) {
                p->healthy = 0;
                close_socket(p->fd);
                p->fd = ST_INVALID_SOCKET;
                return;
            }
            (void)session;
            (void)payload;
            (void)payload_len;
            (void)port_index;
            p->rx_bytes += packet_len;
            p->rx_packets++;
            e->total_rx += packet_len;
            p->last_ack_ms = now;
            p->healthy = 1;
            if ((type == PKT_STATS || type == PKT_HELLO_ACK) && find_sent(e, seq, &sent_ms) == 0) {
                p->rtt_ms = (double)(now - sent_ms);
            }
            memmove(p->rx_buf, p->rx_buf + packet_len, p->rx_len - packet_len);
            p->rx_len -= packet_len;
        }
        if (p->rx_len == ST_STREAM_BUF) {
            p->healthy = 0;
            close_socket(p->fd);
            p->fd = ST_INVALID_SOCKET;
            return;
        }
    }
}

static void receive_client_shared(engine_t *e, uint64_t now) {
    uint8_t buf[ST_MAX_PACKET];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    for (;;) {
        int got;
        uint8_t type = 0;
        uint8_t port_index = 0;
        uint64_t session = 0;
        uint64_t seq = 0;
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint64_t sent_ms = 0;
        uint16_t source_port;
        path_t *p;

        got = (int)recvfrom(e->shared_client_fd, (char *)buf, sizeof(buf), 0,
                            (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (!socket_would_block()) {
                set_status(e, "Client recv error on shared socket");
            }
            break;
        }

        if (verify_packet(buf, (size_t)got, e->key0, e->key1, &type, &port_index,
                          &session, &seq, &payload, &payload_len) != 0) {
            continue;
        }
        (void)session;
        (void)payload;
        (void)payload_len;
        (void)port_index;

        source_port = ntohs(from.sin_port);
        p = find_path(e, PATH_UDP, source_port);
        if (!p && type == PKT_HELLO_ACK) {
            p = add_path(e, PATH_UDP, source_port);
            if (p) {
                p->fd = e->shared_client_fd;
                p->shared_fd = 1;
                p->remote = from;
                p->healthy = 1;
                set_status(e, "Discovered authenticated UDP path on port %u",
                           (unsigned)source_port);
            }
        }
        if (!p) {
            continue;
        }

        p->rx_bytes += (uint64_t)got;
        p->rx_packets++;
        e->total_rx += (uint64_t)got;
        p->last_ack_ms = now;
        p->healthy = 1;

        if ((type == PKT_STATS || type == PKT_HELLO_ACK) && find_sent(e, seq, &sent_ms) == 0) {
            p->rtt_ms = (double)(now - sent_ms);
        }
    }
}

static void client_probe_udp_auto(engine_t *e, uint64_t now) {
    int i;
    for (i = 0; i < ST_SCAN_BURST; i++) {
        struct sockaddr_in remote;
        path_t temp;
        uint64_t seq;
        uint16_t port = e->udp_probe_next_port;

        if (find_path(e, PATH_UDP, port) == NULL &&
            fill_remote_addr(e->cfg.server_ip, port, &remote) == 0) {
            memset(&temp, 0, sizeof(temp));
            temp.port = port;
            temp.fd = e->shared_client_fd;
            temp.remote = remote;
            seq = e->seq++;
            remember_sent(e, seq, now);
            send_packet_path(e, &temp, PKT_HELLO, 0, seq, NULL, 0, NULL);
        }

        if (e->udp_probe_next_port == e->cfg.range_end) {
            e->udp_probe_next_port = e->cfg.range_start;
            e->udp_scan_complete = 1;
            break;
        }
        e->udp_probe_next_port++;
    }
}

static void client_probe_tcp_auto(engine_t *e, uint64_t now) {
    int i;
    for (i = 0; i < ST_TCP_SCAN_BURST; i++) {
        uint16_t port = e->tcp_probe_next_port;
        start_tcp_probe_port(e, port, now);
        if (e->tcp_probe_next_port == e->cfg.range_end) {
            e->tcp_probe_next_port = e->cfg.range_start;
            e->tcp_scan_complete = 1;
            break;
        }
        e->tcp_probe_next_port++;
    }
}

static path_t *choose_path(engine_t *e) {
    int tries;
    if (e->path_count <= 0) {
        return NULL;
    }
    for (tries = 0; tries < e->path_count; tries++) {
        int idx = e->next_path++ % e->path_count;
        path_t *p = &e->paths[idx];
        if (p->healthy || p->last_ack_ms == 0) {
            return p;
        }
    }
    return &e->paths[e->next_path++ % e->path_count];
}

static void client_send_hello(engine_t *e, uint64_t now) {
    int i;
    if (now - e->last_hello_ms < 1000) {
        return;
    }
    for (i = 0; i < e->path_count; i++) {
        uint64_t seq = e->seq++;
        remember_sent(e, seq, now);
        send_packet_path(e, &e->paths[i], PKT_HELLO, (uint8_t)i, seq, NULL, 0, NULL);
    }
    e->last_hello_ms = now;
}

static void client_send_data(engine_t *e, uint64_t now, uint64_t dt_ms) {
    double bytes_per_ms = (e->cfg.rate_mbps * 1000.0 * 1000.0 / 8.0) / 1000.0;
    e->send_credit += bytes_per_ms * (double)dt_ms;
    if (e->send_credit > ST_MAX_PAYLOAD * 64.0) {
        e->send_credit = ST_MAX_PAYLOAD * 64.0;
    }

    while (e->send_credit >= (double)(ST_HEADER_LEN + 64)) {
        uint8_t payload[ST_MAX_PAYLOAD];
        uint16_t payload_len;
        uint64_t seq;
        path_t *p = choose_path(e);
        int idx;
        int i;
        if (!p) {
            return;
        }
        idx = (int)(p - e->paths);
        payload_len = (uint16_t)e->send_credit;
        if (payload_len > ST_MAX_PAYLOAD) {
            payload_len = ST_MAX_PAYLOAD;
        }
        if (payload_len < 64) {
            payload_len = 64;
        }
        seq = e->seq++;
        for (i = 0; i < payload_len; i++) {
            payload[i] = (uint8_t)((seq + (uint64_t)i) & 0xffU);
        }
        remember_sent(e, seq, now);
        if (send_packet_path(e, p, PKT_DATA, (uint8_t)idx, seq, payload, payload_len, NULL) < 0) {
            set_status(e, "Send failed on port %u", (unsigned)p->port);
            return;
        }
        e->send_credit -= (double)(payload_len + ST_HEADER_LEN);
    }
}

static void engine_tick(engine_t *e, uint64_t now, uint64_t dt_ms) {
    int i;
    if (!e->running) {
        return;
    }

    if (e->cfg.mode == MODE_SERVER) {
        int budget = e->path_count < ST_SERVER_RECV_BUDGET ? e->path_count : ST_SERVER_RECV_BUDGET;
        for (i = 0; i < budget; i++) {
            int idx = (e->server_poll_cursor + i) % e->path_count;
            if (e->paths[idx].proto == PATH_TCP) {
                accept_tcp_server(e, &e->paths[idx], idx, now);
            } else {
                receive_server(e, &e->paths[idx], idx, now);
            }
        }
        if (e->path_count > 0) {
            e->server_poll_cursor = (e->server_poll_cursor + budget) % e->path_count;
        }
        receive_tcp_connections(e, now);
    } else {
        complete_tcp_pending(e, now);
        if (e->cfg.auto_ports) {
            if (transport_has_udp(e->cfg.transport)) {
                receive_client_shared(e, now);
                client_probe_udp_auto(e, now);
            }
            if (transport_has_tcp(e->cfg.transport)) {
                for (i = 0; i < e->path_count; i++) {
                    if (e->paths[i].proto == PATH_TCP) {
                        receive_client_tcp(e, &e->paths[i], now);
                    }
                }
                client_probe_tcp_auto(e, now);
            }
        } else {
            for (i = 0; i < e->path_count; i++) {
                if (e->paths[i].proto == PATH_TCP) {
                    receive_client_tcp(e, &e->paths[i], now);
                } else {
                    receive_client(e, &e->paths[i], now);
                }
            }
            client_send_hello(e, now);
        }
        client_send_data(e, now, dt_ms);
    }

    update_rates(e, now);
}

static const char *mode_name(app_mode_t mode) {
    return mode == MODE_SERVER ? "Server" : "Client";
}

static void fmt_rate(double bps, char *out, size_t out_len) {
    const char *unit = "B/s";
    double v = bps;
    if (v >= 1024.0) {
        v /= 1024.0;
        unit = "KiB/s";
    }
    if (v >= 1024.0) {
        v /= 1024.0;
        unit = "MiB/s";
    }
    snprintf(out, out_len, "%.2f %s", v, unit);
}

static void term_enable_color(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(h, mode);
    }
#endif
}

static int term_init(void) {
    term_enable_color();
#ifndef _WIN32
    if (tcgetattr(STDIN_FILENO, &g_old_termios) == 0) {
        struct termios raw = g_old_termios;
        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
            return -1;
        }
        g_old_stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (g_old_stdin_flags >= 0) {
            fcntl(STDIN_FILENO, F_SETFL, g_old_stdin_flags | O_NONBLOCK);
        }
        g_term_active = 1;
    }
#endif
    printf("\x1b[?25l");
    fflush(stdout);
    return 0;
}

static void term_restore(void) {
    printf("\x1b[0m\x1b[?25h\n");
    fflush(stdout);
#ifndef _WIN32
    if (g_term_active) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_old_termios);
        if (g_old_stdin_flags >= 0) {
            fcntl(STDIN_FILENO, F_SETFL, g_old_stdin_flags);
        }
        g_term_active = 0;
    }
#endif
}

static key_event_t read_key(void) {
    key_event_t ev;
    ev.type = KEY_NONE;
    ev.ch = 0;
#ifdef _WIN32
    if (!_kbhit()) {
        return ev;
    }
    ev.ch = _getch();
    if (ev.ch == 0 || ev.ch == 224) {
        int code = _getch();
        if (code == 72) ev.type = KEY_UP;
        else if (code == 80) ev.type = KEY_DOWN;
        else if (code == 75) ev.type = KEY_LEFT;
        else if (code == 77) ev.type = KEY_RIGHT;
        return ev;
    }
    if (ev.ch == '\r' || ev.ch == '\n') ev.type = KEY_ENTER;
    else if (ev.ch == 8 || ev.ch == 127) ev.type = KEY_BACKSPACE;
    else if (ev.ch == 27) ev.type = KEY_ESC;
    else ev.type = KEY_CHAR;
    return ev;
#else
    unsigned char c;
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) {
        return ev;
    }
    if (c == 27) {
        unsigned char seq[2];
        ssize_t n1 = read(STDIN_FILENO, &seq[0], 1);
        ssize_t n2 = read(STDIN_FILENO, &seq[1], 1);
        if (n1 == 1 && n2 == 1 && seq[0] == '[') {
            if (seq[1] == 'A') ev.type = KEY_UP;
            else if (seq[1] == 'B') ev.type = KEY_DOWN;
            else if (seq[1] == 'C') ev.type = KEY_RIGHT;
            else if (seq[1] == 'D') ev.type = KEY_LEFT;
        } else {
            ev.type = KEY_ESC;
        }
        return ev;
    }
    ev.ch = c;
    if (c == '\r' || c == '\n') ev.type = KEY_ENTER;
    else if (c == 127 || c == 8) ev.type = KEY_BACKSPACE;
    else ev.type = KEY_CHAR;
    return ev;
#endif
}

static void draw_line(const char *color, const char *fmt, ...) {
    va_list ap;
    printf("%s", color);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\x1b[0m\n");
}

static void draw_tui(const engine_t *e, int selected, const char *prompt, const char *input) {
    char ports[256];
    char tx[64];
    char rx[64];
    int i;
    int scan_done;
    const char *items[ST_MAX_MENU] = {
        "Mode",
        "Transport",
        "Server IP",
        "Ports",
        "Token",
        "Rate",
        "Start/Stop",
        "Quit"
    };

    ports_to_string(&e->cfg, ports, sizeof(ports));
    fmt_rate(e->tx_bps, tx, sizeof(tx));
    fmt_rate(e->rx_bps, rx, sizeof(rx));
    scan_done = (!transport_has_udp(e->cfg.transport) || e->udp_scan_complete) &&
                (!transport_has_tcp(e->cfg.transport) || e->tcp_scan_complete);

    printf("\x1b[H\x1b[2J");
    draw_line("\x1b[38;5;45m", " sloptunnel");
    draw_line("\x1b[38;5;240m", " -----------------------------------------------");
    printf(" \x1b[38;5;252mMode:\x1b[0m %-8s  \x1b[38;5;252mTransport:\x1b[0m %-5s  \x1b[38;5;252mState:\x1b[0m %-8s  \x1b[38;5;252mPeers:\x1b[0m %d\n",
           mode_name(e->cfg.mode), transport_name(e->cfg.transport),
           e->running ? "running" : "stopped", e->active_peers);
    printf(" \x1b[38;5;252mServer:\x1b[0m %-15s  \x1b[38;5;252mPorts:\x1b[0m %s\n",
           e->cfg.server_ip, ports);
    printf(" \x1b[38;5;252mPaths:\x1b[0m %-5d  \x1b[38;5;252mCapacity:\x1b[0m %-5d  \x1b[38;5;252mScan:\x1b[0m %s\n",
           e->path_count, e->path_capacity,
           e->cfg.auto_ports ? (scan_done ? "cycling" : "probing") : "fixed");
    printf(" \x1b[38;5;252mTX:\x1b[0m %-14s  \x1b[38;5;252mRX:\x1b[0m %-14s  \x1b[38;5;252mTotal:\x1b[0m %" PRIu64 " / %" PRIu64 " bytes\n",
           tx, rx, e->total_tx, e->total_rx);
    printf(" \x1b[38;5;245m%s\x1b[0m\n\n", e->status[0] ? e->status : "Ready");

    for (i = 0; i < ST_MAX_MENU; i++) {
        const char *cursor = i == selected ? "\x1b[48;5;24m\x1b[38;5;231m > " : "   ";
        const char *tail = i == selected ? "\x1b[0m" : "";
        printf("%s%-12s", cursor, items[i]);
        if (i == 0) {
            printf("%s%s\n", mode_name(e->cfg.mode), tail);
        } else if (i == 1) {
            printf("%s%s\n", transport_name(e->cfg.transport), tail);
        } else if (i == 2) {
            printf("%s%s\n", e->cfg.server_ip, tail);
        } else if (i == 3) {
            printf("%s%s\n", ports, tail);
        } else if (i == 4) {
            printf("%s%s\n", e->cfg.token[0] ? "set" : "empty", tail);
        } else if (i == 5) {
            printf("%.2f Mbps%s\n", e->cfg.rate_mbps, tail);
        } else if (i == 6) {
            printf("%s%s\n", e->running ? "Stop" : "Start", tail);
        } else {
            printf("%s\n", tail);
        }
    }

    printf("\n \x1b[38;5;245mPort status%s\x1b[0m\n",
           e->path_count > ST_MAX_MENU_PATHS ? " (first 16)" : "");
    for (i = 0; i < e->path_count && i < ST_MAX_MENU_PATHS; i++) {
        char ptx[64];
        char prx[64];
        fmt_rate(e->paths[i].tx_bps, ptx, sizeof(ptx));
        fmt_rate(e->paths[i].rx_bps, prx, sizeof(prx));
        printf("  \x1b[38;5;252m%3s:%-5u\x1b[0m tx %-12s rx %-12s pkts %" PRIu64 "/%" PRIu64 " rtt %.0fms %s\n",
               proto_name(e->paths[i].proto), (unsigned)e->paths[i].port, ptx, prx,
               e->paths[i].tx_packets, e->paths[i].rx_packets,
               e->paths[i].rtt_ms, e->paths[i].healthy ? "\x1b[38;5;42mup\x1b[0m" : "\x1b[38;5;196mdown\x1b[0m");
    }

    if (prompt) {
        printf("\n \x1b[38;5;220m%s\x1b[0m %s\x1b[?25h", prompt, input ? input : "");
    } else {
        printf("\n \x1b[38;5;240mArrows select, Enter edits/toggles, q quits.\x1b[0m");
    }
    fflush(stdout);
}

static int prompt_text(engine_t *e, int selected, const char *label,
                       const char *initial, char *out, size_t out_len) {
    char buf[256];
    size_t len = 0;
    uint64_t last = 0;
    if (initial) {
        snprintf(buf, sizeof(buf), "%s", initial);
        len = strlen(buf);
    } else {
        buf[0] = '\0';
    }

    for (;;) {
        key_event_t ev;
        uint64_t now = now_ms();
        if (now - last > 33) {
            draw_tui(e, selected, label, buf);
            last = now;
        }
        ev = read_key();
        if (ev.type == KEY_NONE) {
            sleep_ms(10);
            continue;
        }
        if (ev.type == KEY_ENTER) {
            snprintf(out, out_len, "%s", buf);
            printf("\x1b[?25l");
            return 0;
        }
        if (ev.type == KEY_ESC) {
            printf("\x1b[?25l");
            return -1;
        }
        if (ev.type == KEY_BACKSPACE) {
            if (len > 0) {
                buf[--len] = '\0';
            }
        } else if (ev.type == KEY_CHAR && isprint((unsigned char)ev.ch)) {
            if (len + 1 < sizeof(buf)) {
                buf[len++] = (char)ev.ch;
                buf[len] = '\0';
            }
        }
    }
}

static void handle_menu_enter(engine_t *e, int selected) {
    char input[256];
    char current[256];

    if (selected == 0 && !e->running) {
        e->cfg.mode = e->cfg.mode == MODE_CLIENT ? MODE_SERVER : MODE_CLIENT;
        set_status(e, "Mode set to %s", mode_name(e->cfg.mode));
    } else if (selected == 1 && !e->running) {
        if (e->cfg.transport == TRANSPORT_UDP) {
            e->cfg.transport = TRANSPORT_TCP;
        } else if (e->cfg.transport == TRANSPORT_TCP) {
            e->cfg.transport = TRANSPORT_BOTH;
        } else {
            e->cfg.transport = TRANSPORT_UDP;
        }
        set_status(e, "Transport set to %s", transport_name(e->cfg.transport));
    } else if (selected == 2 && !e->running) {
        if (prompt_text(e, selected, "Server IP:", e->cfg.server_ip, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.server_ip, sizeof(e->cfg.server_ip), input);
            set_status(e, "Server IP set");
        }
    } else if (selected == 3 && !e->running) {
        ports_to_string(&e->cfg, current, sizeof(current));
        if (prompt_text(e, selected, "Ports (auto, auto:1-65535, or list):", current, input, sizeof(input)) == 0) {
            if (parse_port_setting(input, &e->cfg) == 0) {
                set_status(e, "Ports updated");
            } else {
                set_status(e, "Invalid port setting");
            }
        }
    } else if (selected == 4 && !e->running) {
        if (prompt_text(e, selected, "Shared token:", e->cfg.token, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.token, sizeof(e->cfg.token), input);
            set_status(e, "Token updated");
        }
    } else if (selected == 5 && !e->running) {
        snprintf(current, sizeof(current), "%.2f", e->cfg.rate_mbps);
        if (prompt_text(e, selected, "Rate Mbps:", current, input, sizeof(input)) == 0) {
            double v = strtod(input, NULL);
            if (v > 0.0 && v <= 10000.0) {
                e->cfg.rate_mbps = v;
                set_status(e, "Rate updated");
            } else {
                set_status(e, "Invalid rate");
            }
        }
    } else if (selected == 6) {
        if (e->running) {
            engine_stop(e);
        } else if (engine_start(e) != 0) {
            e->running = 0;
        }
    } else if (selected == 7) {
        g_stop = 1;
    } else if (e->running) {
        set_status(e, "Stop before editing settings");
    }
}

static int run_tui(config_t cfg) {
    engine_t e;
    int selected = 0;
    uint64_t last_tick;
    memset(&e, 0, sizeof(e));
    e.cfg = cfg;
    set_status(&e, "Ready");

    if (term_init() != 0) {
        fprintf(stderr, "failed to initialize terminal\n");
        return 1;
    }

    last_tick = now_ms();
    while (!g_stop) {
        uint64_t now = now_ms();
        uint64_t dt = now - last_tick;
        key_event_t ev;
        if (dt == 0) {
            dt = 1;
        }
        last_tick = now;
        engine_tick(&e, now, dt);

        ev = read_key();
        if (ev.type == KEY_UP) {
            selected = (selected + ST_MAX_MENU - 1) % ST_MAX_MENU;
        } else if (ev.type == KEY_DOWN) {
            selected = (selected + 1) % ST_MAX_MENU;
        } else if (ev.type == KEY_ENTER) {
            handle_menu_enter(&e, selected);
        } else if (ev.type == KEY_CHAR && (ev.ch == 'q' || ev.ch == 'Q')) {
            g_stop = 1;
        }

        if (now - e.last_draw_ms > 100) {
            draw_tui(&e, selected, NULL, NULL);
            e.last_draw_ms = now;
        }
        sleep_ms(10);
    }

    if (e.running) {
        engine_stop(&e);
    }
    term_restore();
    return 0;
}

static int run_headless(config_t cfg) {
    engine_t e;
    uint64_t last_tick;
    uint64_t last_print = 0;
    memset(&e, 0, sizeof(e));
    e.cfg = cfg;

    if (engine_start(&e) != 0) {
        fprintf(stderr, "%s\n", e.status);
        return 1;
    }

    printf("%s\n", e.status);
    last_tick = now_ms();
    while (!g_stop) {
        uint64_t now = now_ms();
        uint64_t dt = now - last_tick;
        char tx[64];
        char rx[64];
        if (dt == 0) {
            dt = 1;
        }
        last_tick = now;
        engine_tick(&e, now, dt);
        if (now - last_print >= 1000) {
            fmt_rate(e.tx_bps, tx, sizeof(tx));
            fmt_rate(e.rx_bps, rx, sizeof(rx));
            printf("mode=%s paths=%d/%d tx=%s rx=%s total=%" PRIu64 "/%" PRIu64 " peers=%d status=%s\n",
                   mode_name(e.cfg.mode), e.path_count, e.path_capacity,
                   tx, rx, e.total_tx, e.total_rx, e.active_peers, e.status);
            fflush(stdout);
            last_print = now;
        }
        sleep_ms(10);
    }
    engine_stop(&e);
    return 0;
}

static void usage(const char *argv0) {
    printf("usage: %s [--client|--server] [--server-ip IP] [--ports auto|auto:A-B|LIST]\n", argv0);
    printf("          [--transport udp|tcp|both] [--auto-range A-B] [--max-auto-ports N]\n");
    printf("          [--token TOKEN|--token-file PATH]\n");
    printf("          [--rate-mbps N] [--headless] [--help]\n\n");
    printf("examples:\n");
    printf("  %s\n", argv0);
    printf("  %s --server --transport both --ports auto --token secret --headless\n", argv0);
    printf("  %s --client --server-ip 18.219.84.252 --transport both --ports auto --token secret --headless\n", argv0);
    printf("  %s --server --transport tcp --ports auto:1-1024 --headless\n", argv0);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--client") == 0) {
            cfg->mode = MODE_CLIENT;
        } else if (strcmp(argv[i], "--server") == 0) {
            cfg->mode = MODE_SERVER;
        } else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
            if (parse_transport(argv[++i], &cfg->transport) != 0) {
                fprintf(stderr, "invalid transport\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--server-ip") == 0 && i + 1 < argc) {
            copy_text(cfg->server_ip, sizeof(cfg->server_ip), argv[++i]);
        } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            if (parse_port_setting(argv[++i], cfg) != 0) {
                fprintf(stderr, "invalid port setting\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--auto-range") == 0 && i + 1 < argc) {
            if (parse_range(argv[++i], &cfg->range_start, &cfg->range_end) != 0) {
                fprintf(stderr, "invalid auto range\n");
                return -1;
            }
            cfg->auto_ports = 1;
            cfg->port_count = 0;
        } else if (strcmp(argv[i], "--max-auto-ports") == 0 && i + 1 < argc) {
            long v;
            char *end = NULL;
            v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 65535) {
                fprintf(stderr, "invalid max auto ports\n");
                return -1;
            }
            cfg->max_auto_ports = (int)v;
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            copy_text(cfg->token, sizeof(cfg->token), argv[++i]);
        } else if (strcmp(argv[i], "--token-file") == 0 && i + 1 < argc) {
            if (load_token_file(cfg, argv[++i]) != 0) {
                fprintf(stderr, "could not read token file\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--rate-mbps") == 0 && i + 1 < argc) {
            cfg->rate_mbps = strtod(argv[++i], NULL);
            if (cfg->rate_mbps <= 0.0) {
                fprintf(stderr, "invalid rate\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--headless") == 0) {
            cfg->tui = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    config_t cfg;
    int rc;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    config_defaults(&cfg);
    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return 2;
    }

    if (network_init() != 0) {
        fprintf(stderr, "network initialization failed\n");
        return 1;
    }

    rc = cfg.tui ? run_tui(cfg) : run_headless(cfg);
    network_cleanup();
    return rc;
}
