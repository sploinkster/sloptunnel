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
#include <io.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#endif
typedef SOCKET socket_t;
#define ST_INVALID_SOCKET INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
typedef int socket_t;
#define ST_INVALID_SOCKET (-1)
#endif

#ifdef _WIN32
typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR, LPCWSTR, const GUID *);
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(LPCWSTR);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);
typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE *);
typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD *);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE *);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);

static WINTUN_CREATE_ADAPTER_FUNC pWintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC pWintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC pWintunCloseAdapter;
static WINTUN_START_SESSION_FUNC pWintunStartSession;
static WINTUN_END_SESSION_FUNC pWintunEndSession;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC pWintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC pWintunSendPacket;
static WINTUN_RECEIVE_PACKET_FUNC pWintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC pWintunReleaseReceivePacket;
static WINTUN_GET_READ_WAIT_EVENT_FUNC pWintunGetReadWaitEvent;

static LONG WINAPI windows_crash_filter(EXCEPTION_POINTERS *info) {
    DWORD code = info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionCode : 0;
    fprintf(stderr, "unhandled_exception=0x%08lx\n", (unsigned long)code);
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
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
#define ST_DNS_QUERY_BURST 8
#define ST_MAX_TCP_PENDING 128
#define ST_MAX_TCP_CONNS 1024
#define ST_TCP_CONNECT_TIMEOUT_MS 5000
#define ST_SERVER_RECV_BUDGET 512
#define ST_DNS_PORT 53
#define ST_DNS_FRAME_MAX 100
#define ST_DNS_FRAG_HDR 8
#define ST_DNS_FRAG_DATA (ST_DNS_FRAME_MAX - ST_HEADER_LEN - ST_DNS_FRAG_HDR)
#define ST_DNS_QUEUE_MAX 512
#define ST_FRAG_MAX_PACKET 1600
#define ST_MAX_MENU 12
#define ST_DEFAULT_SERVER "18.219.84.252"
#define ST_DEFAULT_TOKEN "change-me"
#define ST_DEFAULT_DNS_DOMAIN "sploinkstersploinkster.online"
#define ST_DEFAULT_TUN_NAME "sloptun0"
#define ST_DEFAULT_TUN_SERVER "10.44.0.1"
#define ST_DEFAULT_TUN_CLIENT "10.44.0.2"
#define ST_DEFAULT_TUN_CIDR "10.44.0.0/24"
#define ST_DEFAULT_TUN_SERVER6 "fd44:534c:4f50::1"
#define ST_DEFAULT_TUN_CLIENT6 "fd44:534c:4f50::2"
#define ST_DEFAULT_TUN_CIDR6 "fd44:534c:4f50::/64"
#define ST_DEFAULT_TUN_MTU 1200

enum {
    PKT_HELLO = 1,
    PKT_HELLO_ACK = 2,
    PKT_DATA = 3,
    PKT_STATS = 4,
    PKT_BYE = 5,
    PKT_DNS_FRAG = 6
};

typedef enum {
    MODE_CLIENT = 0,
    MODE_SERVER = 1
} app_mode_t;

typedef enum {
    TRANSPORT_UDP = 1,
    TRANSPORT_TCP = 2,
    TRANSPORT_DNS = 4,
    TRANSPORT_BOTH = 3,
    TRANSPORT_ALL = 7
} transport_t;

typedef enum {
    PATH_UDP = 1,
    PATH_TCP = 2,
    PATH_DNS = 3
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

typedef enum {
    TUI_PAGE_MAIN = 0,
    TUI_PAGE_TRANSPORT,
    TUI_PAGE_PORTS,
    TUI_PAGE_DNS,
    TUI_PAGE_CONNECTION,
    TUI_PAGE_TUNNEL,
    TUI_PAGE_RUNTIME
} tui_page_t;

typedef struct {
    key_type_t type;
    int ch;
} key_event_t;

typedef struct {
    app_mode_t mode;
    transport_t transport;
    char server_ip[128];
    int vpn_enabled;
    int route_all;
    char tun_name[64];
    char tun_server_ip[32];
    char tun_client_ip[32];
    char tun_cidr[32];
    char tun_server_ip6[64];
    char tun_client_ip6[64];
    char tun_cidr6[64];
    int tun_mtu;
    int ipv6_enabled;
    int dns_enabled;
    char dns_server[32];
    char dns_tunnel_domain[192];
    char dns_tunnel_resolver[64];
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
    uint32_t id;
    uint16_t total_len;
    uint16_t received;
    uint8_t data[ST_FRAG_MAX_PACKET];
    uint8_t seen[ST_FRAG_MAX_PACKET];
} frag_state_t;

typedef struct {
    uint8_t frame[ST_DNS_FRAME_MAX];
    size_t len;
} dns_queue_item_t;

typedef struct {
    int active;
    uint64_t tun_in_bytes;
    uint64_t tun_out_bytes;
    uint64_t tun_in_packets;
    uint64_t tun_out_packets;
    uint64_t dropped_packets;
    uint64_t last_tun_in_bytes;
    uint64_t last_tun_out_bytes;
    double tun_in_bps;
    double tun_out_bps;
#ifdef _WIN32
    HMODULE wintun;
    void *adapter;
    void *session;
    HANDLE read_wait;
#else
    int fd;
    char egress_dev[64];
    char route_dev[64];
    char route_gw[64];
#endif
} vpn_state_t;

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
    uint64_t last_dns_poll_ms;
    uint16_t dns_query_id;
    int server_poll_cursor;
    tcp_pending_t tcp_pending[ST_MAX_TCP_PENDING];
    tcp_conn_t tcp_conns[ST_MAX_TCP_CONNS];
    int tcp_conn_count;
    dns_queue_item_t dns_queue[ST_DNS_QUEUE_MAX];
    int dns_queue_head;
    int dns_queue_tail;
    int dns_queue_count;
    frag_state_t dns_frag_in;
    uint64_t key0;
    uint64_t key1;
    uint64_t session;
    uint64_t seq;
    uint64_t started_ms;
    uint64_t last_rate_ms;
    uint64_t last_hello_ms;
    uint64_t last_draw_ms;
    uint64_t last_diagnostic_ms;
    uint64_t last_enter_ms;
    uint64_t total_tx;
    uint64_t total_rx;
    double tx_bps;
    double rx_bps;
    double send_credit;
    int next_path;
    int running;
    int vpn_pending;
    int active_peers;
    vpn_state_t vpn;
    peer_t peers[32];
    seq_time_t sent[512];
    char status[256];
} engine_t;

static void set_status(engine_t *e, const char *fmt, ...);

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

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
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

#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static void disable_udp_connreset(socket_t fd) {
    BOOL disabled = FALSE;
    DWORD bytes = 0;
    (void)WSAIoctl(fd, SIO_UDP_CONNRESET, &disabled, sizeof(disabled),
                   NULL, 0, &bytes, NULL, NULL);
}
#endif

static int udp_recv_transient_error(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAECONNRESET;
#else
    return socket_would_block();
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
    if (strcmp(text, "dns") == 0) {
        *transport = TRANSPORT_DNS;
        return 0;
    }
    if (strcmp(text, "both") == 0 || strcmp(text, "udp+tcp") == 0 ||
        strcmp(text, "all") == 0) {
        *transport = strcmp(text, "all") == 0 ? TRANSPORT_ALL : TRANSPORT_BOTH;
        return 0;
    }
    if (strcmp(text, "udp+dns") == 0) {
        *transport = (transport_t)(TRANSPORT_UDP | TRANSPORT_DNS);
        return 0;
    }
    if (strcmp(text, "tcp+dns") == 0) {
        *transport = (transport_t)(TRANSPORT_TCP | TRANSPORT_DNS);
        return 0;
    }
    return -1;
}

static int transport_has_udp(transport_t transport) {
    return (transport & TRANSPORT_UDP) != 0;
}

static int transport_has_tcp(transport_t transport) {
    return (transport & TRANSPORT_TCP) != 0;
}

static int transport_has_dns(transport_t transport) {
    return (transport & TRANSPORT_DNS) != 0;
}

static const char *transport_name(transport_t transport) {
    if (transport == TRANSPORT_ALL) {
        return "all";
    }
    if (transport == (TRANSPORT_UDP | TRANSPORT_DNS)) {
        return "udp+dns";
    }
    if (transport == (TRANSPORT_TCP | TRANSPORT_DNS)) {
        return "tcp+dns";
    }
    if (transport == TRANSPORT_DNS) {
        return "dns";
    }
    if (transport == TRANSPORT_TCP) {
        return "tcp";
    }
    if (transport == TRANSPORT_BOTH) {
        return "udp+tcp";
    }
    return "udp";
}

static int process_is_elevated(void) {
#ifdef _WIN32
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &admin_group)) {
        if (!CheckTokenMembership(NULL, admin_group, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_group);
    }
    return is_admin ? 1 : 0;
#else
    return geteuid() == 0;
#endif
}

#ifndef _WIN32
static int fixed_ports_include_privileged(const config_t *cfg) {
    int i;
    if (cfg->auto_ports) {
        return cfg->range_start < 1024;
    }
    for (i = 0; i < cfg->port_count; i++) {
        if (cfg->ports[i] < 1024) {
            return 1;
        }
    }
    return 0;
}
#endif

static int config_requires_elevation(const config_t *cfg, char *reason, size_t reason_len) {
    if (reason_len > 0) {
        reason[0] = '\0';
    }
    if (cfg->vpn_enabled) {
        snprintf(reason, reason_len,
                 "Full-tunnel VPN needs Administrator/root privileges for Wintun/TUN and routes");
        return 1;
    }
#ifndef _WIN32
    if (cfg->mode == MODE_SERVER && transport_has_dns(cfg->transport)) {
        snprintf(reason, reason_len,
                 "DNS tunneling listens on UDP 53; run as root or grant CAP_NET_BIND_SERVICE");
        return 1;
    }
    if (cfg->mode == MODE_SERVER &&
        (transport_has_udp(cfg->transport) || transport_has_tcp(cfg->transport)) &&
        fixed_ports_include_privileged(cfg)) {
        snprintf(reason, reason_len,
                 "Listening below port 1024 needs root or CAP_NET_BIND_SERVICE");
        return 1;
    }
#endif
    return 0;
}

static int preflight_privileges(engine_t *e) {
    char reason[220];
    if (config_requires_elevation(&e->cfg, reason, sizeof(reason)) &&
        !process_is_elevated()) {
        set_status(e, "%s", reason);
        return -1;
    }
    return 0;
}

static const char *proto_name(path_proto_t proto) {
    if (proto == PATH_TCP) {
        return "tcp";
    }
    if (proto == PATH_DNS) {
        return "dns";
    }
    return "udp";
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
    cfg->transport = TRANSPORT_ALL;
    snprintf(cfg->server_ip, sizeof(cfg->server_ip), "%s", ST_DEFAULT_SERVER);
    snprintf(cfg->token, sizeof(cfg->token), "%s", ST_DEFAULT_TOKEN);
    snprintf(cfg->dns_tunnel_domain, sizeof(cfg->dns_tunnel_domain), "%s", ST_DEFAULT_DNS_DOMAIN);
    snprintf(cfg->dns_tunnel_resolver, sizeof(cfg->dns_tunnel_resolver), "%s", ST_DEFAULT_SERVER);
    snprintf(cfg->tun_name, sizeof(cfg->tun_name), "%s", ST_DEFAULT_TUN_NAME);
    snprintf(cfg->tun_server_ip, sizeof(cfg->tun_server_ip), "%s", ST_DEFAULT_TUN_SERVER);
    snprintf(cfg->tun_client_ip, sizeof(cfg->tun_client_ip), "%s", ST_DEFAULT_TUN_CLIENT);
    snprintf(cfg->tun_cidr, sizeof(cfg->tun_cidr), "%s", ST_DEFAULT_TUN_CIDR);
    snprintf(cfg->tun_server_ip6, sizeof(cfg->tun_server_ip6), "%s", ST_DEFAULT_TUN_SERVER6);
    snprintf(cfg->tun_client_ip6, sizeof(cfg->tun_client_ip6), "%s", ST_DEFAULT_TUN_CLIENT6);
    snprintf(cfg->tun_cidr6, sizeof(cfg->tun_cidr6), "%s", ST_DEFAULT_TUN_CIDR6);
    cfg->tun_mtu = ST_DEFAULT_TUN_MTU;
    cfg->ipv6_enabled = 0;
    snprintf(cfg->dns_server, sizeof(cfg->dns_server), "%s", "1.1.1.1");
    cfg->dns_enabled = 1;
    cfg->vpn_enabled = 1;
    cfg->route_all = 1;
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

static void headless_phase(const engine_t *e, const char *phase) {
    if (e->cfg.tui) {
        return;
    }
    printf("phase=%s\n", phase);
    fflush(stdout);
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

static int systemf(const char *fmt, ...) {
    char cmd[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    return system(cmd);
}

#ifdef _WIN32
static void trim_command_output(char *s) {
    size_t n;
    if (!s) {
        return;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

static int command_status_code(int rc) {
    return rc == -1 ? -1 : rc;
}
#endif

#ifdef _WIN32
static int windows_command_capture(const char *cmd, char *out, size_t out_len) {
    char wrapped[2300];
    FILE *p;
    size_t used = 0;
    int rc;
    if (out_len > 0) {
        out[0] = '\0';
    }
    if (snprintf(wrapped, sizeof(wrapped), "%s 2>&1", cmd) >= (int)sizeof(wrapped)) {
        if (out_len > 0) {
            copy_text(out, out_len, "command line too long");
        }
        return -1;
    }
    p = _popen(wrapped, "r");
    if (!p) {
        if (out_len > 0) {
            copy_text(out, out_len, "could not launch helper command");
        }
        return -1;
    }
    while (out_len > 1 && used + 1 < out_len) {
        size_t n = fread(out + used, 1, out_len - used - 1, p);
        used += n;
        out[used] = '\0';
        if (n == 0) {
            break;
        }
    }
    rc = _pclose(p);
    trim_command_output(out);
    return command_status_code(rc);
}

static int windows_commandf(engine_t *e, const char *label, int fatal,
                            const char *fmt, ...) {
    char cmd[2200];
    char output[512];
    va_list ap;
    int n;
    int rc;
    va_start(ap, fmt);
    n = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        set_status(e, "%s failed: helper command line too long", label);
        return fatal ? -1 : 0;
    }
    rc = windows_command_capture(cmd, output, sizeof(output));
    if (rc == 0) {
        return 0;
    }
    if (output[0]) {
        set_status(e, "%s failed: %s", label, output);
    } else {
        set_status(e, "%s failed with exit code %d", label, rc);
    }
    return fatal ? -1 : 0;
}
#endif

#ifndef _WIN32
static int capture_command(const char *cmd, char *out, size_t out_len) {
    FILE *p;
    size_t n;
    if (out_len == 0) {
        return -1;
    }
    out[0] = '\0';
    p = popen(cmd, "r");
    if (!p) {
        return -1;
    }
    n = fread(out, 1, out_len - 1, p);
    out[n] = '\0';
    pclose(p);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' ' || out[n - 1] == '\t')) {
        out[--n] = '\0';
    }
    return n > 0 ? 0 : -1;
}

static int token_after_word(const char *text, const char *word, char *out, size_t out_len) {
    char tmp[512];
    char *tok;
    int next = 0;
    if (strlen(text) >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, text, strlen(text) + 1);
    tok = strtok(tmp, " \t\r\n");
    while (tok) {
        if (next) {
            copy_text(out, out_len, tok);
            return 0;
        }
        next = strcmp(tok, word) == 0;
        tok = strtok(NULL, " \t\r\n");
    }
    return -1;
}

static int capture_route(const char *target, char *dev, size_t dev_len,
                         char *gw, size_t gw_len) {
    char cmd[256];
    char output[512];
    snprintf(cmd, sizeof(cmd), "ip route get %s 2>/dev/null", target);
    if (capture_command(cmd, output, sizeof(output)) != 0) {
        return -1;
    }
    if (token_after_word(output, "dev", dev, dev_len) != 0) {
        return -1;
    }
    if (token_after_word(output, "via", gw, gw_len) != 0) {
        if (gw_len > 0) {
            gw[0] = '\0';
        }
    }
    return 0;
}
#endif

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

static int hex_value(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static size_t hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (out_len < in_len * 2 + 1) {
        return 0;
    }
    for (i = 0; i < in_len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
    return in_len * 2;
}

static int hex_decode(const char *in, uint8_t *out, size_t out_len, size_t *decoded_len) {
    size_t len = strlen(in);
    size_t i;
    if ((len & 1U) != 0 || out_len < len / 2) {
        return -1;
    }
    for (i = 0; i < len; i += 2) {
        int hi = hex_value((unsigned char)in[i]);
        int lo = hex_value((unsigned char)in[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *decoded_len = len / 2;
    return 0;
}

static void normalize_domain(char *domain) {
    size_t n = strlen(domain);
    while (n > 0 && domain[n - 1] == '.') {
        domain[--n] = '\0';
    }
    for (n = 0; domain[n]; n++) {
        domain[n] = (char)tolower((unsigned char)domain[n]);
    }
}

static int dns_write_qname(uint8_t *buf, size_t buf_len, size_t *off, const char *name) {
    char tmp[256];
    char *label;
    size_t len;
    if (!name || !*name || strlen(name) >= sizeof(tmp)) {
        return -1;
    }
    copy_text(tmp, sizeof(tmp), name);
    normalize_domain(tmp);
    label = strtok(tmp, ".");
    while (label) {
        len = strlen(label);
        if (len == 0 || len > 63 || *off + len + 1 >= buf_len) {
            return -1;
        }
        buf[(*off)++] = (uint8_t)len;
        memcpy(buf + *off, label, len);
        *off += len;
        label = strtok(NULL, ".");
    }
    if (*off >= buf_len) {
        return -1;
    }
    buf[(*off)++] = 0;
    return 0;
}

static int dns_read_qname(const uint8_t *buf, size_t len, size_t *off,
                          char *out, size_t out_len) {
    size_t pos = *off;
    size_t used = 0;
    int jumped = 0;
    size_t jump_off = 0;
    int jumps = 0;
    if (out_len == 0) {
        return -1;
    }
    out[0] = '\0';
    for (;;) {
        uint8_t l;
        if (pos >= len) {
            return -1;
        }
        l = buf[pos++];
        if ((l & 0xc0U) == 0xc0U) {
            uint16_t ptr;
            if (pos >= len || ++jumps > 8) {
                return -1;
            }
            ptr = (uint16_t)(((l & 0x3fU) << 8) | buf[pos++]);
            if (!jumped) {
                jump_off = pos;
            }
            jumped = 1;
            pos = ptr;
            continue;
        }
        if (l == 0) {
            break;
        }
        if (l > 63 || pos + l > len) {
            return -1;
        }
        if (used && used + 1 < out_len) {
            out[used++] = '.';
        }
        if (used + l >= out_len) {
            return -1;
        }
        memcpy(out + used, buf + pos, l);
        used += l;
        pos += l;
    }
    out[used] = '\0';
    normalize_domain(out);
    *off = jumped ? jump_off : pos;
    return 0;
}

static int dns_qname_to_frame(const char *qname, const char *domain,
                              uint8_t *frame, size_t frame_cap, size_t *frame_len) {
    char q[256];
    char d[192];
    char hex[256];
    size_t q_len;
    size_t d_len;
    size_t prefix_len;
    size_t used = 0;
    const char *p;
    if (strlen(qname) >= sizeof(q) || strlen(domain) >= sizeof(d)) {
        return -1;
    }
    copy_text(q, sizeof(q), qname);
    copy_text(d, sizeof(d), domain);
    normalize_domain(q);
    normalize_domain(d);
    q_len = strlen(q);
    d_len = strlen(d);
    if (q_len <= d_len + 1 || strcmp(q + q_len - d_len, d) != 0 ||
        q[q_len - d_len - 1] != '.') {
        return -1;
    }
    prefix_len = q_len - d_len - 1;
    if (prefix_len < 3 || q[0] != 'x' || q[1] != '.') {
        return -1;
    }
    p = q + 2;
    while ((size_t)(p - q) < prefix_len) {
        if (*p == '.') {
            p++;
            continue;
        }
        if (used + 1 >= sizeof(hex)) {
            return -1;
        }
        hex[used++] = *p++;
    }
    hex[used] = '\0';
    return hex_decode(hex, frame, frame_cap, frame_len);
}

static int dns_frame_to_name(const uint8_t *frame, size_t frame_len,
                             const char *domain, char *out, size_t out_len) {
    char hex[ST_DNS_FRAME_MAX * 2 + 1];
    size_t hex_len;
    size_t pos = 0;
    size_t used;
    if (frame_len > ST_DNS_FRAME_MAX ||
        hex_encode(frame, frame_len, hex, sizeof(hex)) == 0) {
        return -1;
    }
    used = snprintf(out, out_len, "x");
    if (used >= out_len) {
        return -1;
    }
    hex_len = strlen(hex);
    while (pos < hex_len) {
        size_t chunk = hex_len - pos;
        int n;
        if (chunk > 50) {
            chunk = 50;
        }
        n = snprintf(out + used, out_len - used, ".%.*s", (int)chunk, hex + pos);
        if (n < 0 || (size_t)n >= out_len - used) {
            return -1;
        }
        used += (size_t)n;
        pos += chunk;
    }
    if (snprintf(out + used, out_len - used, ".%s", domain) >= (int)(out_len - used)) {
        return -1;
    }
    return 0;
}

static size_t dns_build_query(uint8_t *out, size_t out_len, uint16_t id,
                              const uint8_t *frame, size_t frame_len,
                              const char *domain) {
    char qname[256];
    size_t off = 12;
    if (out_len < 32 || dns_frame_to_name(frame, frame_len, domain, qname, sizeof(qname)) != 0) {
        return 0;
    }
    memset(out, 0, out_len);
    put_u16(out + 0, id);
    put_u16(out + 2, 0x0100);
    put_u16(out + 4, 1);
    if (dns_write_qname(out, out_len, &off, qname) != 0 || off + 4 > out_len) {
        return 0;
    }
    put_u16(out + off, 16);
    put_u16(out + off + 2, 1);
    off += 4;
    return off;
}

static size_t dns_build_response(uint8_t *out, size_t out_len, const uint8_t *query,
                                 size_t query_len, const uint8_t *frame,
                                 size_t frame_len) {
    size_t off = 12;
    size_t answer_name_off;
    char qname[256];
    char hex[ST_DNS_FRAME_MAX * 2 + 1];
    size_t txt_len;
    (void)qname;
    if (query_len < 12 || frame_len > ST_DNS_FRAME_MAX ||
        hex_encode(frame, frame_len, hex, sizeof(hex)) == 0) {
        return 0;
    }
    if (dns_read_qname(query, query_len, &off, qname, sizeof(qname)) != 0 ||
        off + 4 > query_len) {
        return 0;
    }
    memset(out, 0, out_len);
    memcpy(out, query, off + 4);
    put_u16(out + 2, 0x8180);
    put_u16(out + 4, 1);
    put_u16(out + 6, 1);
    put_u16(out + 8, 0);
    put_u16(out + 10, 0);
    off += 4;
    answer_name_off = off;
    if (off + 12 >= out_len) {
        return 0;
    }
    out[off++] = 0xc0;
    out[off++] = 0x0c;
    put_u16(out + off, 16);
    put_u16(out + off + 2, 1);
    put_u16(out + off + 4, 0);
    put_u16(out + off + 6, 1);
    txt_len = strlen(hex);
    if (txt_len > 255 || off + 10 + 1 + txt_len > out_len) {
        return 0;
    }
    put_u16(out + off + 8, (uint16_t)(txt_len + 1));
    off += 10;
    out[off++] = (uint8_t)txt_len;
    memcpy(out + off, hex, txt_len);
    off += txt_len;
    (void)answer_name_off;
    return off;
}

static int dns_name_in_zone(const char *name, const char *domain) {
    size_t name_len;
    size_t domain_len;
    if (!name || !domain || !*name || !*domain) {
        return 0;
    }
    name_len = strlen(name);
    domain_len = strlen(domain);
    if (name_len == domain_len && strcmp(name, domain) == 0) {
        return 1;
    }
    return name_len > domain_len + 1 &&
           strcmp(name + name_len - domain_len, domain) == 0 &&
           name[name_len - domain_len - 1] == '.';
}

static int dns_add_name_rr(uint8_t *out, size_t out_len, size_t *off,
                           uint16_t type, const char *name) {
    size_t rdlen_off;
    size_t rdata_start;
    if (*off + 12 > out_len) {
        return -1;
    }
    out[(*off)++] = 0xc0;
    out[(*off)++] = 0x0c;
    put_u16(out + *off, type);
    put_u16(out + *off + 2, 1);
    put_u32(out + *off + 4, 30);
    rdlen_off = *off + 8;
    *off += 10;
    rdata_start = *off;
    if (dns_write_qname(out, out_len, off, name) != 0) {
        return -1;
    }
    put_u16(out + rdlen_off, (uint16_t)(*off - rdata_start));
    return 0;
}

static int dns_add_a_rr(uint8_t *out, size_t out_len, size_t *off, const char *ip) {
    struct in_addr addr;
    if (*off + 16 > out_len || inet_pton(AF_INET, ip, &addr) != 1) {
        return -1;
    }
    out[(*off)++] = 0xc0;
    out[(*off)++] = 0x0c;
    put_u16(out + *off, 1);
    put_u16(out + *off + 2, 1);
    put_u32(out + *off + 4, 30);
    put_u16(out + *off + 8, 4);
    *off += 10;
    memcpy(out + *off, &addr, 4);
    *off += 4;
    return 0;
}

static int dns_add_soa_rr(uint8_t *out, size_t out_len, size_t *off,
                          const char *mname, const char *rname) {
    size_t rdlen_off;
    size_t rdata_start;
    if (*off + 12 > out_len) {
        return -1;
    }
    out[(*off)++] = 0xc0;
    out[(*off)++] = 0x0c;
    put_u16(out + *off, 6);
    put_u16(out + *off + 2, 1);
    put_u32(out + *off + 4, 30);
    rdlen_off = *off + 8;
    *off += 10;
    rdata_start = *off;
    if (dns_write_qname(out, out_len, off, mname) != 0 ||
        dns_write_qname(out, out_len, off, rname) != 0 ||
        *off + 20 > out_len) {
        return -1;
    }
    put_u32(out + *off, 1);
    put_u32(out + *off + 4, 300);
    put_u32(out + *off + 8, 60);
    put_u32(out + *off + 12, 86400);
    put_u32(out + *off + 16, 30);
    *off += 20;
    put_u16(out + rdlen_off, (uint16_t)(*off - rdata_start));
    return 0;
}

static size_t dns_build_zone_response(uint8_t *out, size_t out_len,
                                      const uint8_t *query, size_t query_len,
                                      const char *domain, const char *server_ip) {
    char qname[256];
    char zone[192];
    char ns1[256];
    char ns2[256];
    char hostmaster[256];
    size_t off = 12;
    size_t question_end;
    uint16_t qtype;
    uint16_t qclass;
    uint16_t answers = 0;
    if (query_len < 12 || strlen(domain) >= sizeof(zone)) {
        return 0;
    }
    if (dns_read_qname(query, query_len, &off, qname, sizeof(qname)) != 0 ||
        off + 4 > query_len) {
        return 0;
    }
    qtype = get_u16(query + off);
    qclass = get_u16(query + off + 2);
    question_end = off + 4;
    copy_text(zone, sizeof(zone), domain);
    normalize_domain(zone);
    if (!dns_name_in_zone(qname, zone) || (qclass != 1 && qclass != 255)) {
        return 0;
    }
    if (snprintf(ns1, sizeof(ns1), "ns1.%s", zone) >= (int)sizeof(ns1) ||
        snprintf(ns2, sizeof(ns2), "ns2.%s", zone) >= (int)sizeof(ns2) ||
        snprintf(hostmaster, sizeof(hostmaster), "hostmaster.%s", zone) >= (int)sizeof(hostmaster)) {
        return 0;
    }

    memset(out, 0, out_len);
    memcpy(out, query, question_end);
    put_u16(out + 2, 0x8400);
    put_u16(out + 4, 1);
    put_u16(out + 6, 0);
    put_u16(out + 8, 0);
    put_u16(out + 10, 0);
    off = question_end;

    if (qtype == 2 || qtype == 255) {
        if (dns_add_name_rr(out, out_len, &off, 2, ns1) != 0 ||
            dns_add_name_rr(out, out_len, &off, 2, ns2) != 0) {
            return 0;
        }
        answers = 2;
    } else if (qtype == 1 || qtype == 255) {
        if ((strcmp(qname, ns1) == 0 || strcmp(qname, ns2) == 0 ||
             strcmp(qname, zone) == 0) &&
            dns_add_a_rr(out, out_len, &off, server_ip) == 0) {
            answers = 1;
        }
    } else if (qtype == 6) {
        if (dns_add_soa_rr(out, out_len, &off, ns1, hostmaster) != 0) {
            return 0;
        }
        answers = 1;
    }

    if (answers == 0 && qtype != 16) {
        if (dns_add_soa_rr(out, out_len, &off, ns1, hostmaster) != 0) {
            return 0;
        }
        put_u16(out + 8, 1);
    } else {
        put_u16(out + 6, answers);
    }
    return off;
}

static int dns_extract_txt_frame(const uint8_t *buf, size_t len,
                                 uint8_t *frame, size_t frame_cap,
                                 size_t *frame_len) {
    size_t off = 12;
    uint16_t qd;
    uint16_t an;
    uint16_t i;
    if (len < 12) {
        return -1;
    }
    qd = get_u16(buf + 4);
    an = get_u16(buf + 6);
    for (i = 0; i < qd; i++) {
        char qname[256];
        if (dns_read_qname(buf, len, &off, qname, sizeof(qname)) != 0 || off + 4 > len) {
            return -1;
        }
        off += 4;
    }
    for (i = 0; i < an; i++) {
        char name[256];
        uint16_t type;
        uint16_t rdlen;
        if (dns_read_qname(buf, len, &off, name, sizeof(name)) != 0 || off + 10 > len) {
            return -1;
        }
        type = get_u16(buf + off);
        rdlen = get_u16(buf + off + 8);
        off += 10;
        if (off + rdlen > len) {
            return -1;
        }
        if (type == 16 && rdlen > 1 && off + 1 + buf[off] <= off + rdlen) {
            char hex[256];
            size_t txt_len = buf[off];
            if (txt_len >= sizeof(hex)) {
                return -1;
            }
            memcpy(hex, buf + off + 1, txt_len);
            hex[txt_len] = '\0';
            return hex_decode(hex, frame, frame_cap, frame_len);
        }
        off += rdlen;
    }
    return -1;
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

#ifdef _WIN32
    disable_udp_connreset(s);
#endif
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
#ifdef _WIN32
    disable_udp_connreset(s);
#endif
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
    int n = 0;
    if (transport_has_udp(transport)) {
        n++;
    }
    if (transport_has_tcp(transport)) {
        n++;
    }
    if (transport_has_dns(transport)) {
        n++;
    }
    return n > 0 ? n : 1;
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

static int dns_queue_push_frame(engine_t *e, const uint8_t *frame, size_t frame_len) {
    dns_queue_item_t *item;
    if (frame_len > ST_DNS_FRAME_MAX || e->dns_queue_count >= ST_DNS_QUEUE_MAX) {
        e->vpn.dropped_packets++;
        return -1;
    }
    item = &e->dns_queue[e->dns_queue_tail];
    memcpy(item->frame, frame, frame_len);
    item->len = frame_len;
    e->dns_queue_tail = (e->dns_queue_tail + 1) % ST_DNS_QUEUE_MAX;
    e->dns_queue_count++;
    return 0;
}

static int dns_queue_pop_frame(engine_t *e, uint8_t *frame, size_t *frame_len) {
    dns_queue_item_t *item;
    if (e->dns_queue_count <= 0) {
        return -1;
    }
    item = &e->dns_queue[e->dns_queue_head];
    memcpy(frame, item->frame, item->len);
    *frame_len = item->len;
    item->len = 0;
    e->dns_queue_head = (e->dns_queue_head + 1) % ST_DNS_QUEUE_MAX;
    e->dns_queue_count--;
    return 0;
}

static int dns_send_frame_query(engine_t *e, path_t *p, const uint8_t *frame, size_t frame_len) {
    uint8_t dns[512];
    size_t dns_len;
    int sent;
    if (frame_len > ST_DNS_FRAME_MAX) {
        return -1;
    }
    dns_len = dns_build_query(dns, sizeof(dns), ++e->dns_query_id,
                              frame, frame_len, e->cfg.dns_tunnel_domain);
    if (dns_len == 0) {
        return -1;
    }
    sent = (int)sendto(p->fd, (const char *)dns, (int)dns_len, 0,
                       (const struct sockaddr *)&p->remote, sizeof(p->remote));
    if (sent < 0) {
        return socket_would_block() ? 0 : -1;
    }
    p->tx_bytes += (uint64_t)sent;
    p->tx_packets++;
    e->total_tx += (uint64_t)sent;
    return sent;
}

static int dns_send_packet_path(engine_t *e, path_t *p, uint8_t type, uint8_t port_index,
                                uint64_t seq, const uint8_t *payload,
                                uint16_t payload_len) {
    uint8_t frame[ST_DNS_FRAME_MAX];
    size_t frame_len;
    if (payload_len + ST_HEADER_LEN > ST_DNS_FRAME_MAX) {
        return -1;
    }
    frame_len = build_packet(frame, type, port_index, e->session, seq, payload,
                             payload_len, e->key0, e->key1);
    return dns_send_frame_query(e, p, frame, frame_len);
}

static int dns_queue_packet(engine_t *e, uint8_t type, uint8_t port_index,
                            uint64_t seq, const uint8_t *payload,
                            uint16_t payload_len) {
    uint8_t frame[ST_DNS_FRAME_MAX];
    size_t frame_len;
    if (payload_len + ST_HEADER_LEN > ST_DNS_FRAME_MAX) {
        return -1;
    }
    frame_len = build_packet(frame, type, port_index, e->session, seq, payload,
                             payload_len, e->key0, e->key1);
    return dns_queue_push_frame(e, frame, frame_len);
}

static int dns_fragment_send_or_queue(engine_t *e, path_t *p, const uint8_t *packet,
                                      size_t packet_len, int queue_only) {
    uint32_t frag_id = (uint32_t)(e->seq++ & 0xffffffffU);
    size_t off = 0;
    int sent_any = 0;
    int idx = p ? (int)(p - e->paths) : 0;
    if (packet_len > ST_FRAG_MAX_PACKET) {
        return -1;
    }
    while (off < packet_len) {
        uint8_t payload[ST_DNS_FRAG_HDR + ST_DNS_FRAG_DATA];
        size_t chunk = packet_len - off;
        uint64_t seq = e->seq++;
        int rc;
        if (chunk > ST_DNS_FRAG_DATA) {
            chunk = ST_DNS_FRAG_DATA;
        }
        put_u32(payload, frag_id);
        put_u16(payload + 4, (uint16_t)packet_len);
        put_u16(payload + 6, (uint16_t)off);
        memcpy(payload + ST_DNS_FRAG_HDR, packet + off, chunk);
        if (queue_only) {
            rc = dns_queue_packet(e, PKT_DNS_FRAG, (uint8_t)idx, seq, payload,
                                  (uint16_t)(ST_DNS_FRAG_HDR + chunk));
        } else {
            remember_sent(e, seq, now_ms());
            rc = dns_send_packet_path(e, p, PKT_DNS_FRAG, (uint8_t)idx, seq, payload,
                                      (uint16_t)(ST_DNS_FRAG_HDR + chunk));
        }
        if (rc < 0) {
            return sent_any ? sent_any : -1;
        }
        sent_any += rc > 0 ? rc : 1;
        off += chunk;
    }
    return sent_any;
}

static int dns_reassemble_fragment(engine_t *e, const uint8_t *payload,
                                   uint16_t payload_len, uint8_t *packet,
                                   size_t *packet_len) {
    frag_state_t *f = &e->dns_frag_in;
    uint32_t frag_id;
    uint16_t total_len;
    uint16_t off;
    uint16_t chunk_len;
    uint16_t i;
    if (payload_len <= ST_DNS_FRAG_HDR) {
        return -1;
    }
    frag_id = get_u32(payload);
    total_len = get_u16(payload + 4);
    off = get_u16(payload + 6);
    chunk_len = (uint16_t)(payload_len - ST_DNS_FRAG_HDR);
    if (total_len == 0 || total_len > ST_FRAG_MAX_PACKET || off >= total_len ||
        off + chunk_len > total_len) {
        return -1;
    }
    if (f->id != frag_id || f->total_len != total_len) {
        memset(f, 0, sizeof(*f));
        f->id = frag_id;
        f->total_len = total_len;
    }
    for (i = 0; i < chunk_len; i++) {
        if (!f->seen[off + i]) {
            f->seen[off + i] = 1;
            f->received++;
        }
        f->data[off + i] = payload[ST_DNS_FRAG_HDR + i];
    }
    if (f->received >= f->total_len) {
        memcpy(packet, f->data, f->total_len);
        *packet_len = f->total_len;
        memset(f, 0, sizeof(*f));
        return 1;
    }
    return 0;
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

    if (p->proto == PATH_DNS) {
        return dns_send_packet_path(e, p, type, port_index, seq, payload, payload_len);
    }
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

static int safe_token_text(const char *s) {
    size_t i;
    if (!s || !*s) {
        return 0;
    }
    for (i = 0; s[i]; i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '_' ||
              s[i] == '-' || s[i] == ':' || s[i] == '/')) {
            return 0;
        }
    }
    return 1;
}

static int safe_optional_text(const char *s) {
    return !s || !*s || safe_token_text(s);
}

#ifdef _WIN32
static int widen_text(const char *src, wchar_t *dst, size_t dst_count) {
    int n = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)dst_count);
    return n > 0 ? 0 : -1;
}

static int load_wintun(vpn_state_t *vpn) {
    FARPROC fp;
    vpn->wintun = LoadLibraryA("wintun.dll");
    if (!vpn->wintun) {
        return -1;
    }
#define LOAD_PROC(var, sym) do { \
        fp = GetProcAddress(vpn->wintun, sym); \
        memcpy(&(var), &fp, sizeof(var)); \
    } while (0)
    LOAD_PROC(pWintunCreateAdapter, "WintunCreateAdapter");
    LOAD_PROC(pWintunOpenAdapter, "WintunOpenAdapter");
    LOAD_PROC(pWintunCloseAdapter, "WintunCloseAdapter");
    LOAD_PROC(pWintunStartSession, "WintunStartSession");
    LOAD_PROC(pWintunEndSession, "WintunEndSession");
    LOAD_PROC(pWintunAllocateSendPacket, "WintunAllocateSendPacket");
    LOAD_PROC(pWintunSendPacket, "WintunSendPacket");
    LOAD_PROC(pWintunReceivePacket, "WintunReceivePacket");
    LOAD_PROC(pWintunReleaseReceivePacket, "WintunReleaseReceivePacket");
    LOAD_PROC(pWintunGetReadWaitEvent, "WintunGetReadWaitEvent");
#undef LOAD_PROC
    if (!pWintunCreateAdapter || !pWintunOpenAdapter || !pWintunCloseAdapter ||
        !pWintunStartSession || !pWintunEndSession || !pWintunAllocateSendPacket ||
        !pWintunSendPacket || !pWintunReceivePacket || !pWintunReleaseReceivePacket ||
        !pWintunGetReadWaitEvent) {
        return -1;
    }
    return 0;
}
#endif

static int vpn_start(engine_t *e) {
    vpn_state_t *v = &e->vpn;
    const char *local_ip;
    const char *peer_ip;
    const char *local_ip6;
    const char *peer_ip6;
    memset(v, 0, sizeof(*v));
#ifndef _WIN32
    v->fd = ST_INVALID_SOCKET;
#endif
    if (!e->cfg.vpn_enabled) {
        return 0;
    }
    if (!safe_token_text(e->cfg.tun_name) || !safe_token_text(e->cfg.server_ip) ||
        !safe_token_text(e->cfg.tun_server_ip) || !safe_token_text(e->cfg.tun_client_ip) ||
        !safe_token_text(e->cfg.tun_cidr) || !safe_token_text(e->cfg.dns_server) ||
        !safe_token_text(e->cfg.dns_tunnel_domain) ||
        !safe_optional_text(e->cfg.dns_tunnel_resolver) ||
        !safe_token_text(e->cfg.tun_server_ip6) || !safe_token_text(e->cfg.tun_client_ip6) ||
        !safe_token_text(e->cfg.tun_cidr6)) {
        set_status(e, "Unsafe tunnel, server, or DNS setting");
        return -1;
    }
#ifndef _WIN32
    if (strlen(e->cfg.tun_name) >= IFNAMSIZ) {
        set_status(e, "Tunnel name must be shorter than %d characters", IFNAMSIZ);
        return -1;
    }
#endif
    local_ip = e->cfg.mode == MODE_SERVER ? e->cfg.tun_server_ip : e->cfg.tun_client_ip;
    peer_ip = e->cfg.mode == MODE_SERVER ? e->cfg.tun_client_ip : e->cfg.tun_server_ip;
    local_ip6 = e->cfg.mode == MODE_SERVER ? e->cfg.tun_server_ip6 : e->cfg.tun_client_ip6;
    peer_ip6 = e->cfg.mode == MODE_SERVER ? e->cfg.tun_client_ip6 : e->cfg.tun_server_ip6;

#ifdef _WIN32
    {
        wchar_t name_w[96];
        wchar_t type_w[32];
        if (load_wintun(v) != 0) {
            set_status(e, "wintun.dll not found or missing API");
            return -1;
        }
        if (widen_text(e->cfg.tun_name, name_w, sizeof(name_w) / sizeof(name_w[0])) != 0 ||
            widen_text("sloptunnel", type_w, sizeof(type_w) / sizeof(type_w[0])) != 0) {
            set_status(e, "Could not convert adapter name");
            return -1;
        }
        v->adapter = pWintunOpenAdapter(name_w);
        if (!v->adapter) {
            v->adapter = pWintunCreateAdapter(name_w, type_w, NULL);
        }
        if (!v->adapter) {
            set_status(e, "Could not create Wintun adapter");
            return -1;
        }
        v->session = pWintunStartSession(v->adapter, 0x400000);
        if (!v->session) {
            set_status(e, "Could not start Wintun session");
            return -1;
        }
        v->read_wait = pWintunGetReadWaitEvent(v->session);
        if (windows_commandf(e, "Configure Windows tunnel IPv4", 1,
                             "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                             "\"$ErrorActionPreference='Stop'; "
                             "Remove-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue; "
                             "New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 24 -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; "
                             "Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -InterfaceMetric 1 -ErrorAction Stop\"",
                             e->cfg.tun_name, e->cfg.tun_name, local_ip, e->cfg.tun_name) != 0) {
            return -1;
        }
        if (e->cfg.ipv6_enabled) {
            if (windows_commandf(e, "Configure Windows tunnel IPv6", 1,
                                 "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                                 "\"$ErrorActionPreference='Stop'; "
                                 "Remove-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue; "
                                 "New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 64 -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; "
                                 "Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv6 -InterfaceMetric 1 -ErrorAction Stop\"",
                                 e->cfg.tun_name, e->cfg.tun_name, local_ip6,
                                 e->cfg.tun_name) != 0) {
                return -1;
            }
        }
        if (e->cfg.mode == MODE_CLIENT && e->cfg.dns_enabled) {
            windows_commandf(e, "Configure Windows tunnel DNS", 0,
                             "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                             "\"Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses '%s' -ErrorAction Stop\"",
                             e->cfg.tun_name, e->cfg.dns_server);
        }
        if (e->cfg.mode == MODE_CLIENT && e->cfg.route_all) {
            if (windows_commandf(e, "Configure Windows route-all", 1,
                                 "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                                 "\"$ErrorActionPreference='Stop'; "
                                 "$r=Find-NetRoute -RemoteIPAddress '%s' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1; "
                                 "if(!$r){throw 'No existing route to server IP before enabling tunnel'}; "
                                 "if($r.NextHop){New-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null}else{New-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex $r.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null}; "
                                 "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; "
                                 "New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\"",
                                 e->cfg.server_ip, e->cfg.server_ip, e->cfg.server_ip,
                                 e->cfg.tun_name, peer_ip, e->cfg.tun_name, peer_ip) != 0) {
                return -1;
            }
            if (e->cfg.ipv6_enabled) {
                if (windows_commandf(e, "Configure Windows IPv6 route-all", 1,
                                     "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                                     "\"New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; "
                                     "New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\"",
                                     e->cfg.tun_name, peer_ip6, e->cfg.tun_name, peer_ip6) != 0) {
                    return -1;
                }
            }
        }
    }
#else
    {
        struct ifreq ifr;
        int fd;
        fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (fd < 0) {
            set_status(e, "Could not open /dev/net/tun; run as root/admin");
            return -1;
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        copy_text(ifr.ifr_name, sizeof(ifr.ifr_name), e->cfg.tun_name);
        if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
            close(fd);
            set_status(e, "Could not create TUN device %s", e->cfg.tun_name);
            return -1;
        }
        v->fd = fd;
        systemf("ip link set dev %s down >/dev/null 2>&1 || true", e->cfg.tun_name);
        systemf("ip addr flush dev %s >/dev/null 2>&1 || true", e->cfg.tun_name);
        systemf("ip addr add %s/24 dev %s", local_ip, e->cfg.tun_name);
        if (e->cfg.ipv6_enabled) {
            systemf("ip -6 addr add %s/64 dev %s >/dev/null 2>&1 || true",
                    local_ip6, e->cfg.tun_name);
        }
        systemf("ip link set dev %s mtu %d up", e->cfg.tun_name, e->cfg.tun_mtu);

        if (e->cfg.mode == MODE_SERVER) {
            capture_route("1.1.1.1", v->egress_dev, sizeof(v->egress_dev),
                          v->route_gw, sizeof(v->route_gw));
            if (system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true") == -1) {
                set_status(e, "Could not enable IPv4 forwarding");
            }
            if (e->cfg.ipv6_enabled) {
                if (system("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true") == -1) {
                    set_status(e, "Could not enable IPv6 forwarding");
                }
            }
            if (v->egress_dev[0]) {
                systemf("iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE >/dev/null 2>&1 || "
                        "iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE",
                        e->cfg.tun_cidr, v->egress_dev, e->cfg.tun_cidr, v->egress_dev);
                systemf("iptables -C FORWARD -i %s -o %s -j ACCEPT >/dev/null 2>&1 || "
                        "iptables -A FORWARD -i %s -o %s -j ACCEPT",
                        e->cfg.tun_name, v->egress_dev, e->cfg.tun_name, v->egress_dev);
                systemf("iptables -C FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || "
                        "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT",
                        v->egress_dev, e->cfg.tun_name, v->egress_dev, e->cfg.tun_name);
                if (e->cfg.ipv6_enabled) {
                    systemf("command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE >/dev/null 2>&1 || "
                            "command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE >/dev/null 2>&1 || true",
                            e->cfg.tun_cidr6, v->egress_dev, e->cfg.tun_cidr6, v->egress_dev);
                    systemf("command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -C FORWARD -i %s -o %s -j ACCEPT >/dev/null 2>&1 || "
                            "command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -A FORWARD -i %s -o %s -j ACCEPT >/dev/null 2>&1 || true",
                            e->cfg.tun_name, v->egress_dev, e->cfg.tun_name, v->egress_dev);
                    systemf("command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -C FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || "
                            "command -v ip6tables >/dev/null 2>&1 && "
                            "ip6tables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true",
                            v->egress_dev, e->cfg.tun_name, v->egress_dev, e->cfg.tun_name);
                }
            }
        } else if (e->cfg.route_all) {
            capture_route(e->cfg.server_ip, v->route_dev, sizeof(v->route_dev),
                          v->route_gw, sizeof(v->route_gw));
            if (v->route_dev[0] && v->route_gw[0]) {
                systemf("ip route replace %s/32 via %s dev %s",
                        e->cfg.server_ip, v->route_gw, v->route_dev);
            } else if (v->route_dev[0]) {
                systemf("ip route replace %s/32 dev %s", e->cfg.server_ip, v->route_dev);
            }
            systemf("ip route add 0.0.0.0/1 via %s dev %s >/dev/null 2>&1 || true",
                    peer_ip, e->cfg.tun_name);
            systemf("ip route add 128.0.0.0/1 via %s dev %s >/dev/null 2>&1 || true",
                    peer_ip, e->cfg.tun_name);
            if (e->cfg.ipv6_enabled) {
                systemf("ip -6 route add ::/1 via %s dev %s >/dev/null 2>&1 || true",
                        peer_ip6, e->cfg.tun_name);
                systemf("ip -6 route add 8000::/1 via %s dev %s >/dev/null 2>&1 || true",
                        peer_ip6, e->cfg.tun_name);
            }
            if (e->cfg.dns_enabled) {
                systemf("command -v resolvectl >/dev/null 2>&1 && "
                        "resolvectl dns %s %s >/dev/null 2>&1 && "
                        "resolvectl domain %s '~.' >/dev/null 2>&1 && "
                        "resolvectl default-route %s yes >/dev/null 2>&1 || true",
                        e->cfg.tun_name, e->cfg.dns_server,
                        e->cfg.tun_name, e->cfg.tun_name);
            }
        }
    }
#endif
    v->active = 1;
    return 0;
}

static void vpn_stop(engine_t *e) {
    vpn_state_t *v = &e->vpn;
    if (!e->cfg.vpn_enabled && !v->active) {
        return;
    }
#ifdef _WIN32
    if (e->cfg.mode == MODE_CLIENT && e->cfg.route_all) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
                 "powershell -NoProfile -ExecutionPolicy Bypass -Command "
                 "\"Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue; "
                 "Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue; "
                 "Remove-NetRoute -DestinationPrefix '::/1' -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue; "
                 "Remove-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue; "
                 "Remove-NetRoute -DestinationPrefix '%s/32' -Confirm:$false -ErrorAction SilentlyContinue\"",
                 e->cfg.tun_name, e->cfg.tun_name, e->cfg.tun_name,
                 e->cfg.tun_name, e->cfg.server_ip);
        systemf("%s", cmd);
    }
    if (e->cfg.ipv6_enabled) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "powershell -NoProfile -ExecutionPolicy Bypass -Command "
                 "\"Remove-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -Confirm:$false -ErrorAction SilentlyContinue\"",
                 e->cfg.tun_name,
                 e->cfg.mode == MODE_SERVER ? e->cfg.tun_server_ip6 : e->cfg.tun_client_ip6);
        systemf("%s", cmd);
    }
    if (e->cfg.mode == MODE_CLIENT && e->cfg.dns_enabled) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "netsh interface ip set dns name=\"%s\" source=dhcp", e->cfg.tun_name);
        systemf("%s", cmd);
    }
    if (v->session && pWintunEndSession) {
        pWintunEndSession(v->session);
    }
    if (v->adapter && pWintunCloseAdapter) {
        pWintunCloseAdapter(v->adapter);
    }
    if (v->wintun) {
        FreeLibrary(v->wintun);
    }
#else
    if (e->cfg.mode == MODE_CLIENT && e->cfg.route_all) {
        if (e->cfg.dns_enabled) {
            systemf("command -v resolvectl >/dev/null 2>&1 && resolvectl revert %s >/dev/null 2>&1 || true",
                    e->cfg.tun_name);
        }
        systemf("ip route del 0.0.0.0/1 dev %s >/dev/null 2>&1 || true", e->cfg.tun_name);
        systemf("ip route del 128.0.0.0/1 dev %s >/dev/null 2>&1 || true", e->cfg.tun_name);
        if (e->cfg.ipv6_enabled) {
            systemf("ip -6 route del ::/1 dev %s >/dev/null 2>&1 || true", e->cfg.tun_name);
            systemf("ip -6 route del 8000::/1 dev %s >/dev/null 2>&1 || true", e->cfg.tun_name);
        }
        systemf("ip route del %s/32 >/dev/null 2>&1 || true", e->cfg.server_ip);
    }
    if (e->cfg.mode == MODE_SERVER && v->egress_dev[0]) {
        systemf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE >/dev/null 2>&1 || true",
                e->cfg.tun_cidr, v->egress_dev);
        systemf("iptables -D FORWARD -i %s -o %s -j ACCEPT >/dev/null 2>&1 || true",
                e->cfg.tun_name, v->egress_dev);
        systemf("iptables -D FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true",
                v->egress_dev, e->cfg.tun_name);
        if (e->cfg.ipv6_enabled) {
            systemf("command -v ip6tables >/dev/null 2>&1 && "
                    "ip6tables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE >/dev/null 2>&1 || true",
                    e->cfg.tun_cidr6, v->egress_dev);
            systemf("command -v ip6tables >/dev/null 2>&1 && "
                    "ip6tables -D FORWARD -i %s -o %s -j ACCEPT >/dev/null 2>&1 || true",
                    e->cfg.tun_name, v->egress_dev);
            systemf("command -v ip6tables >/dev/null 2>&1 && "
                    "ip6tables -D FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true",
                    v->egress_dev, e->cfg.tun_name);
        }
    }
    if (v->fd >= 0) {
        close(v->fd);
        v->fd = ST_INVALID_SOCKET;
    }
#endif
    memset(v, 0, sizeof(*v));
#ifndef _WIN32
    v->fd = ST_INVALID_SOCKET;
#endif
}

static int vpn_read_packet(engine_t *e, uint8_t *buf, size_t buf_len) {
    vpn_state_t *v = &e->vpn;
    if (!v->active) {
        return 0;
    }
#ifdef _WIN32
    {
        DWORD size = 0;
        BYTE *packet;
        packet = pWintunReceivePacket((WINTUN_SESSION_HANDLE)v->session, &size);
        if (!packet) {
            return 0;
        }
        if (size > buf_len) {
            pWintunReleaseReceivePacket((WINTUN_SESSION_HANDLE)v->session, packet);
            v->dropped_packets++;
            return 0;
        }
        memcpy(buf, packet, size);
        pWintunReleaseReceivePacket((WINTUN_SESSION_HANDLE)v->session, packet);
        return (int)size;
    }
#else
    {
        int n = (int)read(v->fd, buf, buf_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        return n;
    }
#endif
}

static int vpn_write_packet(engine_t *e, const uint8_t *buf, size_t len) {
    vpn_state_t *v = &e->vpn;
    if (!v->active || len == 0) {
        return 0;
    }
#ifdef _WIN32
    {
        BYTE *packet;
        packet = pWintunAllocateSendPacket((WINTUN_SESSION_HANDLE)v->session, (DWORD)len);
        if (!packet) {
            return -1;
        }
        memcpy(packet, buf, len);
        pWintunSendPacket((WINTUN_SESSION_HANDLE)v->session, packet);
        return (int)len;
    }
#else
    {
        int n = (int)write(v->fd, buf, len);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return n;
    }
#endif
}

static void engine_stop(engine_t *e);
static void engine_stop_preserve_status(engine_t *e);

static int engine_start(engine_t *e) {
    int i;
    int capacity;
    uint64_t now;
    headless_phase(e, "engine_start");
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
    e->last_dns_poll_ms = 0;
    e->dns_query_id = (uint16_t)(now_ms() & 0xffffU);
    e->dns_queue_head = 0;
    e->dns_queue_tail = 0;
    e->dns_queue_count = 0;
    memset(&e->dns_frag_in, 0, sizeof(e->dns_frag_in));
    e->server_poll_cursor = 0;
    e->session = random_session_id();
    e->seq = 1;
    now = now_ms();
    e->started_ms = now;
    e->last_rate_ms = e->started_ms;
    e->last_hello_ms = 0;
    e->last_diagnostic_ms = 0;
    e->vpn_pending = 0;
    e->send_credit = 0.0;
    e->next_path = 0;
    e->total_tx = 0;
    e->total_rx = 0;
    e->tx_bps = 0.0;
    e->rx_bps = 0.0;
    derive_key(e->cfg.token, &e->key0, &e->key1);

    if (preflight_privileges(e) != 0) {
        return -1;
    }

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
    headless_phase(e, "paths_allocated");

    if (transport_has_dns(e->cfg.transport)) {
        path_t *p = add_path(e, PATH_DNS, ST_DNS_PORT);
        const char *resolver = e->cfg.dns_tunnel_resolver[0] ?
                               e->cfg.dns_tunnel_resolver : e->cfg.server_ip;
        if (!p) {
            set_status(e, "No capacity for DNS tunnel path");
            engine_stop_preserve_status(e);
            return -1;
        }
        if (e->cfg.mode == MODE_SERVER) {
            if (make_udp_socket(ST_DNS_PORT, 1, NULL, &p->fd, NULL) != 0) {
                e->path_count--;
                set_status(e, "Could not bind DNS UDP port 53");
                engine_stop_preserve_status(e);
                return -1;
            }
        } else {
            if (make_unbound_udp_socket(&p->fd) != 0 ||
                fill_remote_addr(resolver, ST_DNS_PORT, &p->remote) != 0) {
                e->path_count--;
                set_status(e, "Could not create DNS tunnel socket");
                engine_stop_preserve_status(e);
                return -1;
            }
        }
        headless_phase(e, "dns_path_ready");
    }

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
                if (transport_has_dns(e->cfg.transport) && port == ST_DNS_PORT) {
                    continue;
                }
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
            engine_stop_preserve_status(e);
            return -1;
        }
    } else if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        if (transport_has_udp(e->cfg.transport) &&
            make_unbound_udp_socket(&e->shared_client_fd) != 0) {
            set_status(e, "Could not create UDP probe socket");
            engine_stop_preserve_status(e);
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
                        engine_stop_preserve_status(e);
                        return -1;
                    }
                }
                if (transport_has_udp(e->cfg.transport)) {
                    if (transport_has_dns(e->cfg.transport) && e->cfg.ports[i] == ST_DNS_PORT) {
                        continue;
                    }
                    path_t *p = add_path(e, PATH_UDP, e->cfg.ports[i]);
                    if (!p || make_udp_socket(p->port, 1, NULL, &p->fd, NULL) != 0) {
                        if (p) {
                            e->path_count--;
                        }
                        set_status(e, "Could not bind UDP port %u", (unsigned)e->cfg.ports[i]);
                        engine_stop_preserve_status(e);
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
                        engine_stop_preserve_status(e);
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
            engine_stop_preserve_status(e);
            return -1;
        }
    }
    headless_phase(e, "transport_paths_ready");

    if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        struct sockaddr_in probe;
        if (fill_remote_addr(e->cfg.server_ip, e->cfg.range_start, &probe) != 0) {
            set_status(e, "Invalid server IP: %s", e->cfg.server_ip);
            engine_stop_preserve_status(e);
            return -1;
        }
    } else if (e->cfg.mode == MODE_CLIENT) {
        for (i = 0; i < e->path_count; i++) {
            if (e->paths[i].proto == PATH_DNS) {
                continue;
            }
            if (fill_remote_addr(e->cfg.server_ip, e->paths[i].port, &e->paths[i].remote) != 0) {
                set_status(e, "Invalid server IP or socket failure for %s:%u",
                           e->cfg.server_ip, (unsigned)e->paths[i].port);
                engine_stop_preserve_status(e);
                return -1;
            }
        }
    }

    if (e->cfg.mode == MODE_CLIENT && e->cfg.vpn_enabled) {
        e->vpn_pending = 1;
        headless_phase(e, "vpn_deferred_until_auth");
    } else {
        headless_phase(e, "vpn_starting");
        if (vpn_start(e) != 0) {
            engine_stop_preserve_status(e);
            return -1;
        }
        headless_phase(e, "vpn_ready");
    }

    e->running = 1;
    if (e->cfg.auto_ports && e->cfg.mode == MODE_CLIENT) {
        set_status(e, "Client probing %s ports %u-%u with %d path slots",
                   transport_name(e->cfg.transport),
                   (unsigned)e->cfg.range_start, (unsigned)e->cfg.range_end,
                   e->path_capacity);
        if (e->vpn_pending) {
            set_status(e, "Client probing %s ports %u-%u; VPN waits for an authenticated path",
                       transport_name(e->cfg.transport),
                       (unsigned)e->cfg.range_start, (unsigned)e->cfg.range_end);
        }
    } else {
        set_status(e, "%s started with %d %s path%s",
                   e->cfg.mode == MODE_SERVER ? "Server" : "Client",
                   e->path_count, transport_name(e->cfg.transport),
                   e->path_count == 1 ? "" : "s");
        if (e->vpn_pending) {
            set_status(e, "Client started; VPN waits for an authenticated tunnel path");
        }
    }
    return 0;
}

static void engine_stop(engine_t *e) {
    int i;
    vpn_stop(e);
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
    e->vpn_pending = 0;
    set_status(e, "Stopped");
}

static void engine_stop_preserve_status(engine_t *e) {
    char status[sizeof(e->status)];
    copy_text(status, sizeof(status), e->status);
    engine_stop(e);
    if (status[0]) {
        copy_text(e->status, sizeof(e->status), status);
    }
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
    e->vpn.tun_in_bps = ((double)(e->vpn.tun_in_bytes - e->vpn.last_tun_in_bytes) * 1000.0) /
                        (double)elapsed;
    e->vpn.tun_out_bps = ((double)(e->vpn.tun_out_bytes - e->vpn.last_tun_out_bytes) * 1000.0) /
                         (double)elapsed;
    e->vpn.last_tun_in_bytes = e->vpn.tun_in_bytes;
    e->vpn.last_tun_out_bytes = e->vpn.tun_out_bytes;
    e->active_peers = count_active_peers(e, now);
    e->last_rate_ms = now;
}

static int authenticated_path_count(const engine_t *e) {
    int i;
    int n = 0;
    for (i = 0; i < e->path_count; i++) {
        if (e->paths[i].last_ack_ms != 0) {
            n++;
        }
    }
    return n;
}

static int client_scan_complete(const engine_t *e) {
    if (!e->cfg.auto_ports) {
        return 1;
    }
    if (transport_has_udp(e->cfg.transport) && !e->udp_scan_complete) {
        return 0;
    }
    if (transport_has_tcp(e->cfg.transport) && !e->tcp_scan_complete) {
        return 0;
    }
    return 1;
}

static void diagnose_client_connectivity(engine_t *e, uint64_t now) {
    const char *scope;
    if (e->cfg.mode != MODE_CLIENT || !e->running || authenticated_path_count(e) > 0) {
        return;
    }
    if (now - e->started_ms < 6000 || now - e->last_diagnostic_ms < 5000) {
        return;
    }
    e->last_diagnostic_ms = now;
    scope = transport_has_dns(e->cfg.transport) &&
            !(transport_has_udp(e->cfg.transport) || transport_has_tcp(e->cfg.transport)) ?
            "DNS tunnel" : "tunnel";
    if (client_scan_complete(e)) {
        set_status(e, "No authenticated %s paths found; check server IP, token, firewall, and transport settings", scope);
    } else {
        set_status(e, "Waiting for authenticated %s replies; check token/server IP if this persists", scope);
    }
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
            if (!udp_recv_transient_error()) {
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
            if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
                if (vpn_write_packet(e, payload, payload_len) > 0) {
                    e->vpn.tun_out_bytes += payload_len;
                    e->vpn.tun_out_packets++;
                } else {
                    e->vpn.dropped_packets++;
                }
            }
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
    if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
        if (vpn_write_packet(e, payload, payload_len) > 0) {
            e->vpn.tun_out_bytes += payload_len;
            e->vpn.tun_out_packets++;
        } else {
            e->vpn.dropped_packets++;
        }
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
            if (!udp_recv_transient_error()) {
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

        if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
            if (vpn_write_packet(e, payload, payload_len) > 0) {
                e->vpn.tun_out_bytes += payload_len;
                e->vpn.tun_out_packets++;
            } else {
                e->vpn.dropped_packets++;
            }
        }
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
            if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
                if (vpn_write_packet(e, payload, payload_len) > 0) {
                    e->vpn.tun_out_bytes += payload_len;
                    e->vpn.tun_out_packets++;
                } else {
                    e->vpn.dropped_packets++;
                }
            }
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
            if (!udp_recv_transient_error()) {
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

        if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
            if (vpn_write_packet(e, payload, payload_len) > 0) {
                e->vpn.tun_out_bytes += payload_len;
                e->vpn.tun_out_packets++;
            } else {
                e->vpn.dropped_packets++;
            }
        }
        if ((type == PKT_STATS || type == PKT_HELLO_ACK) && find_sent(e, seq, &sent_ms) == 0) {
            p->rtt_ms = (double)(now - sent_ms);
        }
    }
}

static void process_client_dns_frame(engine_t *e, path_t *p, uint8_t *frame,
                                     size_t frame_len, uint64_t now) {
    uint8_t type = 0;
    uint8_t port_index = 0;
    uint64_t session = 0;
    uint64_t seq = 0;
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;
    uint64_t sent_ms = 0;
    uint8_t packet[ST_FRAG_MAX_PACKET];
    size_t packet_len = 0;
    if (verify_packet(frame, frame_len, e->key0, e->key1, &type, &port_index,
                      &session, &seq, &payload, &payload_len) != 0) {
        return;
    }
    (void)session;
    (void)port_index;
    p->rx_bytes += (uint64_t)frame_len;
    p->rx_packets++;
    e->total_rx += (uint64_t)frame_len;
    p->last_ack_ms = now;
    p->healthy = 1;

    if (type == PKT_DNS_FRAG) {
        int rc = dns_reassemble_fragment(e, payload, payload_len, packet, &packet_len);
        if (rc > 0 && e->vpn.active) {
            if (vpn_write_packet(e, packet, packet_len) > 0) {
                e->vpn.tun_out_bytes += packet_len;
                e->vpn.tun_out_packets++;
            } else {
                e->vpn.dropped_packets++;
            }
        } else if (rc < 0) {
            e->vpn.dropped_packets++;
        }
    } else if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
        if (vpn_write_packet(e, payload, payload_len) > 0) {
            e->vpn.tun_out_bytes += payload_len;
            e->vpn.tun_out_packets++;
        } else {
            e->vpn.dropped_packets++;
        }
    }
    if ((type == PKT_STATS || type == PKT_HELLO_ACK) && find_sent(e, seq, &sent_ms) == 0) {
        p->rtt_ms = (double)(now - sent_ms);
    }
}

static void receive_client_dns(engine_t *e, path_t *p, uint64_t now) {
    uint8_t buf[768];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    for (;;) {
        uint8_t frame[ST_DNS_FRAME_MAX];
        size_t frame_len = 0;
        int got = (int)recvfrom(p->fd, (char *)buf, sizeof(buf), 0,
                                (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (!udp_recv_transient_error()) {
                set_status(e, "DNS recv error");
            }
            break;
        }
        if (dns_extract_txt_frame(buf, (size_t)got, frame, sizeof(frame), &frame_len) == 0) {
            process_client_dns_frame(e, p, frame, frame_len, now);
        }
    }
}

static void receive_server_dns(engine_t *e, path_t *p, int index, uint64_t now) {
    uint8_t buf[768];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    for (;;) {
        int got;
        char qname[256];
        size_t off = 12;
        uint8_t frame[ST_DNS_FRAME_MAX];
        uint8_t reply_frame[ST_DNS_FRAME_MAX];
        size_t frame_len = 0;
        size_t reply_len = 0;
        uint8_t type = 0;
        uint8_t port_index = 0;
        uint64_t session = 0;
        uint64_t seq = 0;
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint8_t packet[ST_FRAG_MAX_PACKET];
        size_t packet_len = 0;
        uint8_t response[768];
        size_t response_len;

        got = (int)recvfrom(p->fd, (char *)buf, sizeof(buf), 0,
                            (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (!udp_recv_transient_error()) {
                set_status(e, "DNS server recv error");
            }
            break;
        }
        if ((size_t)got < 12 ||
            dns_read_qname(buf, (size_t)got, &off, qname, sizeof(qname)) != 0) {
            continue;
        }
        if (dns_qname_to_frame(qname, e->cfg.dns_tunnel_domain, frame, sizeof(frame), &frame_len) != 0 ||
            verify_packet(frame, frame_len, e->key0, e->key1, &type, &port_index,
                          &session, &seq, &payload, &payload_len) != 0) {
            response_len = dns_build_zone_response(response, sizeof(response), buf, (size_t)got,
                                                   e->cfg.dns_tunnel_domain, e->cfg.server_ip);
            if (response_len > 0) {
                int sent = (int)sendto(p->fd, (const char *)response, (int)response_len, 0,
                                       (struct sockaddr *)&from, from_len);
                if (sent > 0) {
                    p->tx_bytes += (uint64_t)sent;
                    p->tx_packets++;
                    e->total_tx += (uint64_t)sent;
                }
            }
            continue;
        }

        p->rx_bytes += (uint64_t)got;
        p->rx_packets++;
        e->total_rx += (uint64_t)got;
        mark_peer(e, session, now, (size_t)got);
        p->remote = from;

        if (type == PKT_DNS_FRAG) {
            int rc = dns_reassemble_fragment(e, payload, payload_len, packet, &packet_len);
            if (rc > 0 && e->vpn.active) {
                if (vpn_write_packet(e, packet, packet_len) > 0) {
                    e->vpn.tun_out_bytes += packet_len;
                    e->vpn.tun_out_packets++;
                } else {
                    e->vpn.dropped_packets++;
                }
            } else if (rc < 0) {
                e->vpn.dropped_packets++;
            }
        } else if (type == PKT_DATA && e->vpn.active && payload_len > 0) {
            if (vpn_write_packet(e, payload, payload_len) > 0) {
                e->vpn.tun_out_bytes += payload_len;
                e->vpn.tun_out_packets++;
            } else {
                e->vpn.dropped_packets++;
            }
        }

        if (dns_queue_pop_frame(e, reply_frame, &reply_len) != 0) {
            reply_len = build_packet(reply_frame, type == PKT_HELLO ? PKT_HELLO_ACK : PKT_STATS,
                                     (uint8_t)index, e->session, seq, NULL, 0,
                                     e->key0, e->key1);
        }
        response_len = dns_build_response(response, sizeof(response), buf, (size_t)got,
                                          reply_frame, reply_len);
        if (response_len > 0) {
            int sent = (int)sendto(p->fd, (const char *)response, (int)response_len, 0,
                                   (struct sockaddr *)&from, from_len);
            if (sent > 0) {
                p->tx_bytes += (uint64_t)sent;
                p->tx_packets++;
                e->total_tx += (uint64_t)sent;
            }
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

static void client_probe_tcp_fixed(engine_t *e, uint64_t now) {
    int i;
    for (i = 0; i < e->cfg.port_count; i++) {
        start_tcp_probe_port(e, e->cfg.ports[i], now);
    }
}

static void client_poll_dns(engine_t *e, uint64_t now) {
    int i;
    int burst;
    if (now - e->last_dns_poll_ms < 50) {
        return;
    }
    for (i = 0; i < e->path_count; i++) {
        if (e->paths[i].proto == PATH_DNS) {
            for (burst = 0; burst < ST_DNS_QUERY_BURST; burst++) {
                uint64_t seq = e->seq++;
                remember_sent(e, seq, now);
                send_packet_path(e, &e->paths[i], PKT_HELLO, (uint8_t)i, seq, NULL, 0, NULL);
            }
        }
    }
    e->last_dns_poll_ms = now;
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

static int server_send_tunnel_packet(engine_t *e, const uint8_t *payload, uint16_t payload_len) {
    int tries;
    if (e->path_count <= 0) {
        return -1;
    }
    for (tries = 0; tries < e->path_count; tries++) {
        int idx = e->next_path++ % e->path_count;
        path_t *p = &e->paths[idx];
        uint64_t seq;
        int sent = -1;
        if (!p->healthy) {
            continue;
        }
        seq = e->seq++;
        if (p->proto == PATH_UDP) {
            if (p->rx_packets == 0) {
                continue;
            }
            sent = send_packet_path(e, p, PKT_DATA, (uint8_t)idx, seq, payload, payload_len, NULL);
        } else if (p->proto == PATH_DNS) {
            sent = dns_fragment_send_or_queue(e, p, payload, payload_len, 1);
        } else {
            int i;
            for (i = 0; i < e->tcp_conn_count; i++) {
                if (e->tcp_conns[i].path_index == idx && socket_valid(e->tcp_conns[i].fd)) {
                    sent = send_packet_fd(e, e->tcp_conns[i].fd, PKT_DATA, (uint8_t)idx,
                                          seq, payload, payload_len);
                    if (sent > 0) {
                        p->tx_bytes += (uint64_t)sent;
                        p->tx_packets++;
                        e->total_tx += (uint64_t)sent;
                    }
                    break;
                }
            }
        }
        if (sent > 0) {
            remember_sent(e, seq, now_ms());
            return sent;
        }
    }
    return -1;
}

static void vpn_pump_tun(engine_t *e, uint64_t now) {
    uint8_t packet[ST_MAX_PAYLOAD];
    int budget = 64;
    while (budget-- > 0) {
        int n = vpn_read_packet(e, packet, sizeof(packet));
        int sent = -1;
        uint64_t seq;
        if (n == 0) {
            return;
        }
        if (n < 0) {
            set_status(e, "TUN read failed");
            return;
        }
        e->vpn.tun_in_bytes += (uint64_t)n;
        e->vpn.tun_in_packets++;
        if (e->cfg.mode == MODE_SERVER) {
            sent = server_send_tunnel_packet(e, packet, (uint16_t)n);
        } else {
            path_t *p = choose_path(e);
            int idx;
            if (!p) {
                e->vpn.dropped_packets++;
                continue;
            }
            idx = (int)(p - e->paths);
            if (p->proto == PATH_DNS) {
                sent = dns_fragment_send_or_queue(e, p, packet, (size_t)n, 0);
            } else {
                seq = e->seq++;
                remember_sent(e, seq, now);
                sent = send_packet_path(e, p, PKT_DATA, (uint8_t)idx, seq,
                                        packet, (uint16_t)n, NULL);
            }
        }
        if (sent <= 0) {
            e->vpn.dropped_packets++;
        }
    }
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
        if (p->proto == PATH_DNS && payload_len > ST_DNS_FRAG_DATA) {
            payload_len = ST_DNS_FRAG_DATA;
        }
        if (payload_len < 64) {
            payload_len = p->proto == PATH_DNS ? ST_DNS_FRAG_DATA : 64;
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

static int maybe_start_client_vpn(engine_t *e) {
    if (!e->vpn_pending || e->vpn.active || e->cfg.mode != MODE_CLIENT) {
        return 0;
    }
    if (authenticated_path_count(e) <= 0) {
        return 0;
    }
    set_status(e, "Authenticated path ready; enabling full-tunnel VPN");
    if (vpn_start(e) != 0) {
        engine_stop_preserve_status(e);
        return -1;
    }
    e->vpn_pending = 0;
    set_status(e, "VPN enabled over authenticated tunnel path");
    return 1;
}

static void engine_tick(engine_t *e, uint64_t now, uint64_t dt_ms) {
    int i;
    if (!e->running) {
        return;
    }

    if (e->cfg.mode == MODE_SERVER) {
        int budget = e->path_count < ST_SERVER_RECV_BUDGET ? e->path_count : ST_SERVER_RECV_BUDGET;
        for (i = 0; i < e->path_count; i++) {
            if (e->paths[i].proto == PATH_DNS) {
                receive_server_dns(e, &e->paths[i], i, now);
            }
        }
        for (i = 0; i < budget; i++) {
            int idx = (e->server_poll_cursor + i) % e->path_count;
            if (e->paths[idx].proto == PATH_TCP) {
                accept_tcp_server(e, &e->paths[idx], idx, now);
            } else if (e->paths[idx].proto == PATH_DNS) {
                continue;
            } else {
                receive_server(e, &e->paths[idx], idx, now);
            }
        }
        if (e->path_count > 0) {
            e->server_poll_cursor = (e->server_poll_cursor + budget) % e->path_count;
        }
        receive_tcp_connections(e, now);
        if (e->vpn.active) {
            vpn_pump_tun(e, now);
        }
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
            if (transport_has_dns(e->cfg.transport)) {
                for (i = 0; i < e->path_count; i++) {
                    if (e->paths[i].proto == PATH_DNS) {
                        receive_client_dns(e, &e->paths[i], now);
                    }
                }
                client_poll_dns(e, now);
            }
        } else {
            if (transport_has_tcp(e->cfg.transport)) {
                client_probe_tcp_fixed(e, now);
            }
            for (i = 0; i < e->path_count; i++) {
                if (e->paths[i].proto == PATH_TCP) {
                    receive_client_tcp(e, &e->paths[i], now);
                } else if (e->paths[i].proto == PATH_DNS) {
                    receive_client_dns(e, &e->paths[i], now);
                } else {
                    receive_client(e, &e->paths[i], now);
                }
            }
            client_send_hello(e, now);
            if (transport_has_dns(e->cfg.transport)) {
                client_poll_dns(e, now);
            }
        }
        if (maybe_start_client_vpn(e) < 0) {
            return;
        }
        if (e->vpn.active) {
            vpn_pump_tun(e, now);
        } else {
            client_send_data(e, now, dt_ms);
        }
    }

    diagnose_client_connectivity(e, now);
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
    printf("\x1b[?1049h\x1b[H\x1b[?25l");
    fflush(stdout);
    return 0;
}

static void term_restore(void) {
    printf("\x1b[0m\x1b[?25h\x1b[?1049l\n");
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
    printf("\x1b[0m\x1b[K\n");
}

static const char *tui_page_name(tui_page_t page) {
    if (page == TUI_PAGE_TRANSPORT) {
        return "Transport";
    }
    if (page == TUI_PAGE_PORTS) {
        return "Port Scan";
    }
    if (page == TUI_PAGE_DNS) {
        return "DNS Tunnel";
    }
    if (page == TUI_PAGE_CONNECTION) {
        return "Connection";
    }
    if (page == TUI_PAGE_TUNNEL) {
        return "Tunnel";
    }
    if (page == TUI_PAGE_RUNTIME) {
        return "Runtime";
    }
    return "Main";
}

static tui_page_t tui_parent_page(tui_page_t page) {
    if (page == TUI_PAGE_PORTS || page == TUI_PAGE_DNS) {
        return TUI_PAGE_TRANSPORT;
    }
    return TUI_PAGE_MAIN;
}

typedef enum {
    TUI_TRANSPORT_PROTOCOL = 0,
    TUI_TRANSPORT_PORTS,
    TUI_TRANSPORT_DNS,
    TUI_TRANSPORT_BACK
} tui_transport_item_t;

typedef enum {
    TUI_PORT_MODE = 0,
    TUI_PORT_RANGE,
    TUI_PORT_FIXED,
    TUI_PORT_MAX,
    TUI_PORT_BACK
} tui_port_item_t;

typedef enum {
    TUI_DNS_DOMAIN = 0,
    TUI_DNS_RESOLVER,
    TUI_DNS_BACK
} tui_dns_item_t;

typedef enum {
    TUI_CONN_ROLE = 0,
    TUI_CONN_SERVER_IP,
    TUI_CONN_TOKEN,
    TUI_CONN_RATE,
    TUI_CONN_BACK
} tui_connection_item_t;

typedef enum {
    TUI_TUNNEL_MODE = 0,
    TUI_TUNNEL_ROUTE_ALL,
    TUI_TUNNEL_IPV6,
    TUI_TUNNEL_ADAPTER,
    TUI_TUNNEL_DNS,
    TUI_TUNNEL_BACK
} tui_tunnel_item_t;

static int tui_transport_has_ports(const config_t *cfg) {
    return transport_has_udp(cfg->transport) || transport_has_tcp(cfg->transport);
}

static int tui_transport_has_dns(const config_t *cfg) {
    return transport_has_dns(cfg->transport);
}

static tui_transport_item_t tui_transport_item_for_row(const config_t *cfg, int row) {
    if (row == 0) {
        return TUI_TRANSPORT_PROTOCOL;
    }
    row--;
    if (tui_transport_has_ports(cfg)) {
        if (row == 0) {
            return TUI_TRANSPORT_PORTS;
        }
        row--;
    }
    if (tui_transport_has_dns(cfg)) {
        if (row == 0) {
            return TUI_TRANSPORT_DNS;
        }
    }
    return TUI_TRANSPORT_BACK;
}

static tui_port_item_t tui_port_item_for_row(const config_t *cfg, int row) {
    if (row == 0) {
        return TUI_PORT_MODE;
    }
    row--;
    if (cfg->auto_ports) {
        if (row == 0) {
            return TUI_PORT_RANGE;
        }
        row--;
        if (row == 0) {
            return TUI_PORT_MAX;
        }
    } else {
        if (row == 0) {
            return TUI_PORT_FIXED;
        }
    }
    return TUI_PORT_BACK;
}

static tui_dns_item_t tui_dns_item_for_row(const config_t *cfg, int row) {
    if (row == 0) {
        return TUI_DNS_DOMAIN;
    }
    row--;
    if (cfg->mode == MODE_CLIENT) {
        if (row == 0) {
            return TUI_DNS_RESOLVER;
        }
    }
    return TUI_DNS_BACK;
}

static tui_connection_item_t tui_connection_item_for_row(const config_t *cfg, int row) {
    if (row == 0) {
        return TUI_CONN_ROLE;
    }
    row--;
    if (cfg->mode == MODE_CLIENT) {
        if (row == 0) {
            return TUI_CONN_SERVER_IP;
        }
        row--;
    }
    if (row == 0) {
        return TUI_CONN_TOKEN;
    }
    row--;
    if (!cfg->vpn_enabled) {
        if (row == 0) {
            return TUI_CONN_RATE;
        }
    }
    return TUI_CONN_BACK;
}

static tui_tunnel_item_t tui_tunnel_item_for_row(const config_t *cfg, int row) {
    if (row == 0) {
        return TUI_TUNNEL_MODE;
    }
    row--;
    if (cfg->vpn_enabled) {
        if (cfg->mode == MODE_CLIENT) {
            if (row == 0) {
                return TUI_TUNNEL_ROUTE_ALL;
            }
            row--;
        }
        if (row == 0) {
            return TUI_TUNNEL_IPV6;
        }
        row--;
        if (row == 0) {
            return TUI_TUNNEL_ADAPTER;
        }
        row--;
        if (cfg->mode == MODE_CLIENT) {
            if (row == 0) {
                return TUI_TUNNEL_DNS;
            }
        }
    }
    return TUI_TUNNEL_BACK;
}

static int tui_item_count(const engine_t *e, tui_page_t page) {
    if (page == TUI_PAGE_MAIN) {
        return 6;
    }
    if (page == TUI_PAGE_TRANSPORT) {
        return 2 + (tui_transport_has_ports(&e->cfg) ? 1 : 0) +
               (tui_transport_has_dns(&e->cfg) ? 1 : 0);
    }
    if (page == TUI_PAGE_PORTS) {
        return e->cfg.auto_ports ? 4 : 3;
    }
    if (page == TUI_PAGE_DNS) {
        return 2 + (e->cfg.mode == MODE_CLIENT ? 1 : 0);
    }
    if (page == TUI_PAGE_CONNECTION) {
        return 3 + (e->cfg.mode == MODE_CLIENT ? 1 : 0) +
               (!e->cfg.vpn_enabled ? 1 : 0);
    }
    if (page == TUI_PAGE_TUNNEL) {
        if (!e->cfg.vpn_enabled) {
            return 2;
        }
        return 4 + (e->cfg.mode == MODE_CLIENT ? 2 : 0);
    }
    return 1;
}

static void cycle_transport(config_t *cfg) {
    if (cfg->transport == TRANSPORT_UDP) {
        cfg->transport = TRANSPORT_TCP;
    } else if (cfg->transport == TRANSPORT_TCP) {
        cfg->transport = TRANSPORT_DNS;
    } else if (cfg->transport == TRANSPORT_DNS) {
        cfg->transport = TRANSPORT_BOTH;
    } else if (cfg->transport == TRANSPORT_BOTH) {
        cfg->transport = (transport_t)(TRANSPORT_UDP | TRANSPORT_DNS);
    } else if (cfg->transport == (transport_t)(TRANSPORT_UDP | TRANSPORT_DNS)) {
        cfg->transport = (transport_t)(TRANSPORT_TCP | TRANSPORT_DNS);
    } else if (cfg->transport == (transport_t)(TRANSPORT_TCP | TRANSPORT_DNS)) {
        cfg->transport = TRANSPORT_ALL;
    } else {
        cfg->transport = TRANSPORT_UDP;
    }
}

static void tui_item_text(const engine_t *e, tui_page_t page, int selected,
                          char *label, size_t label_len, char *value, size_t value_len,
                          char *desc, size_t desc_len) {
    char ports[256];
    ports_to_string(&e->cfg, ports, sizeof(ports));
    label[0] = value[0] = desc[0] = '\0';

    if (page == TUI_PAGE_MAIN) {
        if (selected == 0) {
            copy_text(label, label_len, "Transport");
            copy_text(value, value_len, transport_name(e->cfg.transport));
            copy_text(desc, desc_len, "Open protocol settings. Names are udp, tcp, dns, udp+tcp, udp+dns, tcp+dns, or all; there is no trailing h.");
        } else if (selected == 1) {
            copy_text(label, label_len, "Connection");
            copy_text(value, value_len, e->cfg.mode == MODE_CLIENT ? e->cfg.server_ip : "server role");
            copy_text(desc, desc_len, e->cfg.vpn_enabled ?
                      "Open endpoint settings: client/server role, server address, and shared token." :
                      "Open endpoint settings: role, server address, token, and benchmark rate.");
        } else if (selected == 2) {
            copy_text(label, label_len, "Tunnel / VPN");
            copy_text(value, value_len, e->cfg.vpn_enabled ? "full tunnel" : "benchmark");
            copy_text(desc, desc_len, e->cfg.vpn_enabled ?
                      "Open OS routing and adapter settings. Full tunnel routes normal traffic through the tunnel." :
                      "Benchmark mode skips OS routing and adapter fields.");
        } else if (selected == 3) {
            copy_text(label, label_len, "Runtime");
            snprintf(value, value_len, "%d/%d paths", e->path_count, e->path_capacity);
            copy_text(desc, desc_len, "Open live path counters and per-transport bandwidth details.");
        } else if (selected == 4) {
            copy_text(label, label_len, e->running ? "Stop" : "Start");
            copy_text(value, value_len, e->running ? "running" : "stopped");
            copy_text(desc, desc_len, e->running ? "Stop the current client/server engine and restore routes." : "Start with the current settings.");
        } else {
            copy_text(label, label_len, "Quit");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Exit the TUI. Running tunnels are stopped before exit.");
        }
        return;
    }

    if (page == TUI_PAGE_TRANSPORT) {
        tui_transport_item_t item = tui_transport_item_for_row(&e->cfg, selected);
        if (item == TUI_TRANSPORT_PROTOCOL) {
            copy_text(label, label_len, "Protocol set");
            copy_text(value, value_len, transport_name(e->cfg.transport));
            copy_text(desc, desc_len, "Select which carriers are used. Stacked choices send traffic across multiple methods for more aggregate bandwidth.");
        } else if (item == TUI_TRANSPORT_PORTS) {
            copy_text(label, label_len, "Port scan");
            copy_text(value, value_len, e->cfg.auto_ports ? "auto scan" : "fixed list");
            copy_text(desc, desc_len, "Open outbound UDP/TCP scan settings. Auto scan means you do not have to manually test thousands of ports.");
        } else if (item == TUI_TRANSPORT_DNS) {
            copy_text(label, label_len, "DNS tunnel");
            copy_text(value, value_len, e->cfg.dns_tunnel_domain);
            copy_text(desc, desc_len, "Open DNS tunnel domain and resolver settings.");
        } else {
            copy_text(label, label_len, "Back");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Return to the main page.");
        }
        return;
    }

    if (page == TUI_PAGE_PORTS) {
        tui_port_item_t item = tui_port_item_for_row(&e->cfg, selected);
        if (item == TUI_PORT_MODE) {
            copy_text(label, label_len, "Scan mode");
            copy_text(value, value_len, e->cfg.auto_ports ? "auto scan" : "fixed list");
            copy_text(desc, desc_len, "Auto scan probes the configured range and keeps ports that answer with the tunnel token. Fixed list only tries the ports you enter.");
        } else if (item == TUI_PORT_RANGE) {
            copy_text(label, label_len, "Scan range");
            snprintf(value, value_len, "%u-%u", (unsigned)e->cfg.range_start,
                     (unsigned)e->cfg.range_end);
            copy_text(desc, desc_len, "Range used by auto scan for UDP/TCP outbound connectivity. Example: 1-1024 or 80-9000.");
        } else if (item == TUI_PORT_FIXED) {
            copy_text(label, label_len, "Fixed ports");
            copy_text(value, value_len, ports[0] ? ports : "empty");
            copy_text(desc, desc_len, "Explicit masquerade ports when scan mode is fixed. Example: 80,443,5223.");
        } else if (item == TUI_PORT_MAX) {
            copy_text(label, label_len, "Max paths");
            snprintf(value, value_len, "%d", e->cfg.max_auto_ports);
            copy_text(desc, desc_len, "Maximum number of scanned ports kept in memory per transport. Lower this if you only need the first working paths.");
        } else {
            copy_text(label, label_len, "Back");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Return to the Transport page.");
        }
        return;
    }

    if (page == TUI_PAGE_DNS) {
        tui_dns_item_t item = tui_dns_item_for_row(&e->cfg, selected);
        if (item == TUI_DNS_DOMAIN) {
            copy_text(label, label_len, "Domain");
            copy_text(value, value_len, e->cfg.dns_tunnel_domain);
            copy_text(desc, desc_len, "Authoritative domain used for DNS tunneling. TXT queries carry authenticated tunnel frames under this zone.");
        } else if (item == TUI_DNS_RESOLVER) {
            copy_text(label, label_len, "Resolver");
            copy_text(value, value_len, e->cfg.dns_tunnel_resolver[0] ? e->cfg.dns_tunnel_resolver : e->cfg.server_ip);
            copy_text(desc, desc_len, "Resolver IP used by the client for DNS tunnel queries. Behind a firewall this is usually the allowed DNS resolver.");
        } else {
            copy_text(label, label_len, "Back");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Return to the Transport page.");
        }
        return;
    }

    if (page == TUI_PAGE_CONNECTION) {
        tui_connection_item_t item = tui_connection_item_for_row(&e->cfg, selected);
        if (item == TUI_CONN_ROLE) {
            copy_text(label, label_len, "Role");
            copy_text(value, value_len, mode_name(e->cfg.mode));
            copy_text(desc, desc_len, "Client runs on this machine and connects out. Server listens and forwards tunneled packets.");
        } else if (item == TUI_CONN_SERVER_IP) {
            copy_text(label, label_len, "Server IP");
            copy_text(value, value_len, e->cfg.server_ip);
            copy_text(desc, desc_len, "Remote server address used by clients and DNS zone responses.");
        } else if (item == TUI_CONN_TOKEN) {
            copy_text(label, label_len, "Token");
            copy_text(value, value_len, e->cfg.token[0] ? "set" : "empty");
            copy_text(desc, desc_len, "Shared secret used to authenticate tunnel frames. Client and server must use the same token.");
        } else if (item == TUI_CONN_RATE) {
            copy_text(label, label_len, "Rate");
            snprintf(value, value_len, "%.2f Mbps", e->cfg.rate_mbps);
            copy_text(desc, desc_len, "Benchmark sender target rate when VPN mode is off. It does not cap normal full-tunnel traffic.");
        } else {
            copy_text(label, label_len, "Back");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Return to the main page.");
        }
        return;
    }

    if (page == TUI_PAGE_TUNNEL) {
        tui_tunnel_item_t item = tui_tunnel_item_for_row(&e->cfg, selected);
        if (item == TUI_TUNNEL_MODE) {
            copy_text(label, label_len, "VPN mode");
            copy_text(value, value_len, e->cfg.vpn_enabled ? "full tunnel" : "benchmark");
            copy_text(desc, desc_len, "Full tunnel creates a TUN/Wintun adapter. Benchmark mode only sends synthetic test traffic.");
        } else if (item == TUI_TUNNEL_ROUTE_ALL) {
            copy_text(label, label_len, "Route all");
            copy_text(value, value_len, e->cfg.route_all ? "enabled" : "disabled");
            copy_text(desc, desc_len, "When enabled, client default routes are split through the tunnel while preserving a direct route to the server.");
        } else if (item == TUI_TUNNEL_IPV6) {
            copy_text(label, label_len, "IPv6");
            copy_text(value, value_len, e->cfg.ipv6_enabled ? "enabled" : "disabled");
            copy_text(desc, desc_len, "Adds IPv6 tunnel addresses and routes in addition to IPv4 where supported.");
        } else if (item == TUI_TUNNEL_ADAPTER) {
            copy_text(label, label_len, "Adapter name");
            copy_text(value, value_len, e->cfg.tun_name);
            copy_text(desc, desc_len, "Name for the Linux TUN device or Windows Wintun adapter.");
        } else if (item == TUI_TUNNEL_DNS) {
            copy_text(label, label_len, "Tunnel DNS");
            copy_text(value, value_len, e->cfg.dns_enabled ? e->cfg.dns_server : "disabled");
            copy_text(desc, desc_len, "DNS server assigned to the tunnel adapter in full-tunnel client mode. Enter an empty value to disable it.");
        } else {
            copy_text(label, label_len, "Back");
            copy_text(value, value_len, "");
            copy_text(desc, desc_len, "Return to the main page.");
        }
        return;
    }

    copy_text(label, label_len, "Back");
    copy_text(value, value_len, "");
    copy_text(desc, desc_len, "Return to the main page.");
}

static void draw_runtime_paths(const engine_t *e) {
    int i;
    printf(" \x1b[38;5;245mPaths%s\x1b[0m\x1b[K\n\x1b[K\n",
           e->path_count > ST_MAX_MENU_PATHS ? " (first 16)" : "");
    if (e->path_count == 0) {
        printf("   No active paths yet.\x1b[K\n\x1b[K\n");
        return;
    }
    for (i = 0; i < e->path_count && i < ST_MAX_MENU_PATHS; i++) {
        char ptx[64];
        char prx[64];
        fmt_rate(e->paths[i].tx_bps, ptx, sizeof(ptx));
        fmt_rate(e->paths[i].rx_bps, prx, sizeof(prx));
        printf("   \x1b[38;5;252m%-3s %-5u\x1b[0m  tx %-12s  rx %-12s  rtt %6.0fms  %s\x1b[K\n",
               proto_name(e->paths[i].proto), (unsigned)e->paths[i].port, ptx, prx,
               e->paths[i].rtt_ms, e->paths[i].healthy ? "\x1b[38;5;42mup\x1b[0m" : "\x1b[38;5;196mdown\x1b[0m");
    }
    printf("\x1b[K\n");
}

static void draw_tui(const engine_t *e, tui_page_t page, int selected,
                     const char *prompt, const char *input) {
    char tx[64];
    char rx[64];
    char tun_in[64];
    char tun_out[64];
    char label[48];
    char value[256];
    char desc[320];
    int i;
    int count = tui_item_count(e, page);

    fmt_rate(e->tx_bps, tx, sizeof(tx));
    fmt_rate(e->rx_bps, rx, sizeof(rx));
    fmt_rate(e->vpn.tun_in_bps, tun_in, sizeof(tun_in));
    fmt_rate(e->vpn.tun_out_bps, tun_out, sizeof(tun_out));
    if (selected < 0 || selected >= count) {
        selected = 0;
    }
    tui_item_text(e, page, selected, label, sizeof(label), value, sizeof(value),
                  desc, sizeof(desc));

    printf("\x1b[H");
    draw_line("\x1b[38;5;45m", " sloptunnel");
    printf(" \x1b[38;5;240m%s\x1b[0m\x1b[K\n\x1b[K\n", tui_page_name(page));

    printf("   \x1b[38;5;252mState\x1b[0m       %-10s   \x1b[38;5;252mRole\x1b[0m %-8s   \x1b[38;5;252mTransport\x1b[0m %s\x1b[K\n",
           e->running ? "running" : "stopped", mode_name(e->cfg.mode),
           transport_name(e->cfg.transport));
    printf("   \x1b[38;5;252mTX/RX\x1b[0m       %-12s / %-12s   \x1b[38;5;252mPaths\x1b[0m %d/%d\x1b[K\n",
           tx, rx, e->path_count, e->path_capacity);
    printf("   \x1b[38;5;252mVPN I/O\x1b[0m     %-12s / %-12s   \x1b[38;5;252mDrops\x1b[0m %" PRIu64 "\x1b[K\n\x1b[K\n",
           tun_in, tun_out, e->vpn.dropped_packets);
    printf("   \x1b[38;5;245m%s\x1b[0m\x1b[K\n\x1b[K\n", e->status[0] ? e->status : "Ready");

    if (page == TUI_PAGE_RUNTIME) {
        draw_runtime_paths(e);
    }

    for (i = 0; i < count; i++) {
        char row_label[48];
        char row_value[256];
        char row_desc[320];
        const char *cursor = i == selected ? "\x1b[48;5;24m\x1b[38;5;231m > " : "   ";
        const char *tail = i == selected ? "\x1b[0m" : "";
        tui_item_text(e, page, i, row_label, sizeof(row_label),
                      row_value, sizeof(row_value), row_desc, sizeof(row_desc));
        (void)row_desc;
        printf("%s%-18s %-42s%s\x1b[K\n", cursor, row_label, row_value, tail);
        if (i < count - 1) {
            printf("\x1b[K\n");
        }
    }

    printf("\x1b[K\n   \x1b[38;5;245m%s\x1b[0m\x1b[K\n\x1b[K\n", desc);

    if (prompt) {
        printf("   \x1b[38;5;220m%s\x1b[0m %s\x1b[?25h\x1b[J", prompt, input ? input : "");
    } else {
        printf("   \x1b[38;5;240mUp/Down select, Enter open/edit, Left/Esc back, q quit.\x1b[0m\x1b[J");
    }
    fflush(stdout);
}

static int prompt_text(engine_t *e, tui_page_t page, int selected, const char *label,
                       const char *initial, char *out, size_t out_len) {
    char buf[256];
    size_t len = 0;
    int dirty = 1;
    if (initial) {
        snprintf(buf, sizeof(buf), "%s", initial);
        len = strlen(buf);
    } else {
        buf[0] = '\0';
    }

    for (;;) {
        key_event_t ev;
        if (dirty) {
            draw_tui(e, page, selected, label, buf);
            dirty = 0;
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
                dirty = 1;
            }
        } else if (ev.type == KEY_CHAR && isprint((unsigned char)ev.ch)) {
            if (len + 1 < sizeof(buf)) {
                buf[len++] = (char)ev.ch;
                buf[len] = '\0';
                dirty = 1;
            }
        }
    }
}

static void maybe_pause_on_windows_error(const config_t *cfg) {
#ifdef _WIN32
    if (cfg && cfg->tui && _isatty(_fileno(stdin))) {
        int ch;
        fprintf(stderr, "\nPress Enter to exit...");
        fflush(stderr);
        do {
            ch = getchar();
        } while (ch != '\n' && ch != '\r' && ch != EOF);
    }
#else
    (void)cfg;
#endif
}

static void handle_menu_enter(engine_t *e, tui_page_t *page, int *selected) {
    char input[256];
    char current[256];
    int item = *selected;
    int count = tui_item_count(e, *page);

    if (*page == TUI_PAGE_MAIN) {
        if (item == 0) {
            *page = TUI_PAGE_TRANSPORT;
            *selected = 0;
        } else if (item == 1) {
            *page = TUI_PAGE_CONNECTION;
            *selected = 0;
        } else if (item == 2) {
            *page = TUI_PAGE_TUNNEL;
            *selected = 0;
        } else if (item == 3) {
            *page = TUI_PAGE_RUNTIME;
            *selected = 0;
        } else if (item == 4) {
            if (e->running) {
                engine_stop(e);
            } else if (engine_start(e) != 0) {
                e->running = 0;
            }
        } else {
            g_stop = 1;
        }
        return;
    }

    if (*page == TUI_PAGE_RUNTIME || item == count - 1) {
        *page = tui_parent_page(*page);
        *selected = 0;
        return;
    }

    if (*page == TUI_PAGE_TRANSPORT) {
        tui_transport_item_t transport_item = tui_transport_item_for_row(&e->cfg, item);
        if (transport_item == TUI_TRANSPORT_PORTS) {
            *page = TUI_PAGE_PORTS;
            *selected = 0;
            return;
        }
        if (transport_item == TUI_TRANSPORT_DNS) {
            *page = TUI_PAGE_DNS;
            *selected = 0;
            return;
        }
    }

    if (e->running) {
        set_status(e, "Stop before editing settings");
        return;
    }

    if (*page == TUI_PAGE_TRANSPORT &&
        tui_transport_item_for_row(&e->cfg, item) == TUI_TRANSPORT_PROTOCOL) {
        cycle_transport(&e->cfg);
        if (*selected >= tui_item_count(e, *page)) {
            *selected = tui_item_count(e, *page) - 1;
        }
        set_status(e, "Transport set to %s", transport_name(e->cfg.transport));
    } else if (*page == TUI_PAGE_PORTS &&
               tui_port_item_for_row(&e->cfg, item) == TUI_PORT_MODE) {
        e->cfg.auto_ports = !e->cfg.auto_ports;
        if (e->cfg.auto_ports) {
            e->cfg.port_count = 0;
        }
        if (*selected >= tui_item_count(e, *page)) {
            *selected = tui_item_count(e, *page) - 1;
        }
        set_status(e, "Port scan %s", e->cfg.auto_ports ? "enabled" : "disabled");
    } else if (*page == TUI_PAGE_PORTS &&
               tui_port_item_for_row(&e->cfg, item) == TUI_PORT_RANGE) {
        snprintf(current, sizeof(current), "%u-%u", (unsigned)e->cfg.range_start,
                 (unsigned)e->cfg.range_end);
        if (prompt_text(e, *page, item, "Scan range:", current, input, sizeof(input)) == 0) {
            if (parse_range(input, &e->cfg.range_start, &e->cfg.range_end) == 0) {
                e->cfg.auto_ports = 1;
                e->cfg.port_count = 0;
                set_status(e, "Scan range updated");
            } else {
                set_status(e, "Invalid scan range");
            }
        }
    } else if (*page == TUI_PAGE_PORTS &&
               tui_port_item_for_row(&e->cfg, item) == TUI_PORT_FIXED) {
        uint16_t parsed[ST_MAX_CONFIG_PORTS];
        int parsed_count = 0;
        if (e->cfg.auto_ports) {
            current[0] = '\0';
        } else {
            ports_to_string(&e->cfg, current, sizeof(current));
        }
        if (prompt_text(e, *page, item, "Fixed ports:", current, input, sizeof(input)) == 0) {
            if (parse_ports(input, parsed, &parsed_count) == 0) {
                memcpy(e->cfg.ports, parsed, (size_t)parsed_count * sizeof(parsed[0]));
                e->cfg.port_count = parsed_count;
                e->cfg.auto_ports = 0;
                set_status(e, "Fixed ports updated");
            } else {
                set_status(e, "Invalid fixed port list");
            }
        }
    } else if (*page == TUI_PAGE_PORTS &&
               tui_port_item_for_row(&e->cfg, item) == TUI_PORT_MAX) {
        snprintf(current, sizeof(current), "%d", e->cfg.max_auto_ports);
        if (prompt_text(e, *page, item, "Max scanned paths:", current, input, sizeof(input)) == 0) {
            long v;
            char *end = NULL;
            v = strtol(input, &end, 10);
            if (end && *end == '\0' && v >= 1 && v <= 65535) {
                e->cfg.max_auto_ports = (int)v;
                set_status(e, "Max paths updated");
            } else {
                set_status(e, "Invalid max paths");
            }
        }
    } else if (*page == TUI_PAGE_DNS &&
               tui_dns_item_for_row(&e->cfg, item) == TUI_DNS_DOMAIN) {
        if (prompt_text(e, *page, item, "DNS tunnel domain:", e->cfg.dns_tunnel_domain, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.dns_tunnel_domain, sizeof(e->cfg.dns_tunnel_domain), input);
            normalize_domain(e->cfg.dns_tunnel_domain);
            set_status(e, "DNS tunnel domain set");
        }
    } else if (*page == TUI_PAGE_DNS &&
               tui_dns_item_for_row(&e->cfg, item) == TUI_DNS_RESOLVER) {
        if (prompt_text(e, *page, item, "DNS resolver IP:", e->cfg.dns_tunnel_resolver, input, sizeof(input)) == 0) {
            copy_text(e->cfg.dns_tunnel_resolver, sizeof(e->cfg.dns_tunnel_resolver), input);
            set_status(e, input[0] ? "DNS resolver set" : "DNS resolver will use Server IP");
        }
    } else if (*page == TUI_PAGE_CONNECTION &&
               tui_connection_item_for_row(&e->cfg, item) == TUI_CONN_ROLE) {
        e->cfg.mode = e->cfg.mode == MODE_CLIENT ? MODE_SERVER : MODE_CLIENT;
        if (*selected >= tui_item_count(e, *page)) {
            *selected = tui_item_count(e, *page) - 1;
        }
        set_status(e, "Mode set to %s", mode_name(e->cfg.mode));
    } else if (*page == TUI_PAGE_CONNECTION &&
               tui_connection_item_for_row(&e->cfg, item) == TUI_CONN_SERVER_IP) {
        if (prompt_text(e, *page, item, "Server IP:", e->cfg.server_ip, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.server_ip, sizeof(e->cfg.server_ip), input);
            set_status(e, "Server IP set");
        }
    } else if (*page == TUI_PAGE_CONNECTION &&
               tui_connection_item_for_row(&e->cfg, item) == TUI_CONN_TOKEN) {
        if (prompt_text(e, *page, item, "Shared token:", e->cfg.token, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.token, sizeof(e->cfg.token), input);
            set_status(e, "Token updated");
        }
    } else if (*page == TUI_PAGE_CONNECTION &&
               tui_connection_item_for_row(&e->cfg, item) == TUI_CONN_RATE) {
        snprintf(current, sizeof(current), "%.2f", e->cfg.rate_mbps);
        if (prompt_text(e, *page, item, "Rate Mbps:", current, input, sizeof(input)) == 0) {
            double v = strtod(input, NULL);
            if (v > 0.0 && v <= 10000.0) {
                e->cfg.rate_mbps = v;
                set_status(e, "Rate updated");
            } else {
                set_status(e, "Invalid rate");
            }
        }
    } else if (*page == TUI_PAGE_TUNNEL &&
               tui_tunnel_item_for_row(&e->cfg, item) == TUI_TUNNEL_MODE) {
        e->cfg.vpn_enabled = !e->cfg.vpn_enabled;
        if (*selected >= tui_item_count(e, *page)) {
            *selected = tui_item_count(e, *page) - 1;
        }
        set_status(e, "VPN mode %s", e->cfg.vpn_enabled ? "enabled" : "disabled");
    } else if (*page == TUI_PAGE_TUNNEL &&
               tui_tunnel_item_for_row(&e->cfg, item) == TUI_TUNNEL_ROUTE_ALL) {
        e->cfg.route_all = !e->cfg.route_all;
        set_status(e, "Route-all %s", e->cfg.route_all ? "enabled" : "disabled");
    } else if (*page == TUI_PAGE_TUNNEL &&
               tui_tunnel_item_for_row(&e->cfg, item) == TUI_TUNNEL_IPV6) {
        e->cfg.ipv6_enabled = !e->cfg.ipv6_enabled;
        set_status(e, "IPv6 %s", e->cfg.ipv6_enabled ? "enabled" : "disabled");
    } else if (*page == TUI_PAGE_TUNNEL &&
               tui_tunnel_item_for_row(&e->cfg, item) == TUI_TUNNEL_ADAPTER) {
        if (prompt_text(e, *page, item, "Adapter name:", e->cfg.tun_name, input, sizeof(input)) == 0 && input[0]) {
            copy_text(e->cfg.tun_name, sizeof(e->cfg.tun_name), input);
            set_status(e, "Adapter name set");
        }
    } else if (*page == TUI_PAGE_TUNNEL &&
               tui_tunnel_item_for_row(&e->cfg, item) == TUI_TUNNEL_DNS) {
        if (prompt_text(e, *page, item, "Tunnel DNS server:", e->cfg.dns_server, input, sizeof(input)) == 0) {
            if (input[0]) {
                copy_text(e->cfg.dns_server, sizeof(e->cfg.dns_server), input);
                e->cfg.dns_enabled = 1;
                set_status(e, "Tunnel DNS set");
            } else {
                e->cfg.dns_enabled = 0;
                set_status(e, "Tunnel DNS disabled");
            }
        }
    }
}

static int run_tui(config_t cfg) {
    engine_t *e;
    tui_page_t page = TUI_PAGE_MAIN;
    int selected = 0;
    int dirty = 1;
    char current[220];
    uint64_t last_tick;
    e = (engine_t *)calloc(1, sizeof(*e));
    if (!e) {
        fprintf(stderr, "out of memory allocating engine\n");
        return 1;
    }
    e->cfg = cfg;
    set_status(e, "Ready");
    if (config_requires_elevation(&e->cfg, current, sizeof(current)) &&
        !process_is_elevated()) {
        set_status(e, "%s", current);
    }

    if (term_init() != 0) {
        fprintf(stderr, "error: failed to initialize terminal\n");
        maybe_pause_on_windows_error(&cfg);
        free(e);
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
        engine_tick(e, now, dt);

        ev = read_key();
        if (ev.type == KEY_UP) {
            int count = tui_item_count(e, page);
            selected = (selected + count - 1) % count;
            dirty = 1;
        } else if (ev.type == KEY_DOWN) {
            int count = tui_item_count(e, page);
            selected = (selected + 1) % count;
            dirty = 1;
        } else if (ev.type == KEY_ENTER) {
            if (now - e->last_enter_ms > 250) {
                e->last_enter_ms = now;
                handle_menu_enter(e, &page, &selected);
                dirty = 1;
            }
        } else if (ev.type == KEY_LEFT || ev.type == KEY_ESC ||
                   (ev.type == KEY_BACKSPACE && page != TUI_PAGE_MAIN)) {
            if (page != TUI_PAGE_MAIN) {
                page = tui_parent_page(page);
                selected = 0;
                dirty = 1;
            }
        } else if (ev.type == KEY_CHAR && (ev.ch == 'q' || ev.ch == 'Q')) {
            g_stop = 1;
        }

        if (dirty || now - e->last_draw_ms > (e->running ? 1000U : 500U)) {
            draw_tui(e, page, selected, NULL, NULL);
            e->last_draw_ms = now;
            dirty = 0;
        }
        sleep_ms(10);
    }

    if (e->running) {
        engine_stop(e);
    }
    term_restore();
    free(e);
    return 0;
}

static int run_headless(config_t cfg) {
    engine_t *e;
    uint64_t last_tick;
    uint64_t last_print = 0;
    e = (engine_t *)calloc(1, sizeof(*e));
    if (!e) {
        fprintf(stderr, "out of memory allocating engine\n");
        return 1;
    }
    e->cfg = cfg;

    if (engine_start(e) != 0) {
        fprintf(stderr, "error: %s\n", e->status);
        maybe_pause_on_windows_error(&cfg);
        free(e);
        return 1;
    }

    printf("%s\n", e->status);
    last_tick = now_ms();
    while (!g_stop) {
        uint64_t now = now_ms();
        uint64_t dt = now - last_tick;
        char tx[64];
        char rx[64];
        char tun_in[64];
        char tun_out[64];
        if (dt == 0) {
            dt = 1;
        }
        last_tick = now;
        engine_tick(e, now, dt);
        if (now - last_print >= 1000) {
            fmt_rate(e->tx_bps, tx, sizeof(tx));
            fmt_rate(e->rx_bps, rx, sizeof(rx));
            fmt_rate(e->vpn.tun_in_bps, tun_in, sizeof(tun_in));
            fmt_rate(e->vpn.tun_out_bps, tun_out, sizeof(tun_out));
            printf("mode=%s paths=%d/%d tx=%s rx=%s tun_in=%s tun_out=%s drops=%" PRIu64 " total=%" PRIu64 "/%" PRIu64 " peers=%d status=%s\n",
                   mode_name(e->cfg.mode), e->path_count, e->path_capacity,
                   tx, rx, tun_in, tun_out, e->vpn.dropped_packets,
                   e->total_tx, e->total_rx, e->active_peers, e->status);
            fflush(stdout);
            last_print = now;
        }
        sleep_ms(10);
    }
    engine_stop(e);
    free(e);
    return 0;
}

static void usage(const char *argv0) {
    printf("usage: %s [--client|--server] [--server-ip IP] [--ports auto|auto:A-B|LIST]\n", argv0);
    printf("          [--transport udp|tcp|dns|udp+tcp|udp+dns|tcp+dns|all]\n");
    printf("          [--auto-range A-B] [--max-auto-ports N]\n");
    printf("          [--vpn|--no-vpn] [--no-route] [--tun-name NAME] [--tun-mtu N]\n");
    printf("          [--tun-server-ip IP] [--tun-client-ip IP] [--tun-cidr CIDR]\n");
    printf("          [--ipv6|--no-ipv6] [--tun-server-ip6 IP] [--tun-client-ip6 IP] [--tun-cidr6 CIDR]\n");
    printf("          [--dns-server IP|--no-dns] [--dns-tunnel-domain DOMAIN] [--dns-resolver IP]\n");
    printf("          [--token TOKEN|--token-file PATH]\n");
    printf("          [--rate-mbps N] [--headless] [--help]\n\n");
    printf("examples:\n");
    printf("  %s\n", argv0);
    printf("  %s --server --transport all --ports auto --token secret --headless\n", argv0);
    printf("  %s --client --server-ip 18.219.84.252 --transport all --ports auto --token secret --headless\n", argv0);
    printf("  %s --client --transport dns --dns-tunnel-domain sploinkstersploinkster.online --headless\n", argv0);
    printf("  %s --server --transport tcp --ports auto:1-1024 --headless\n", argv0);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--client") == 0) {
            cfg->mode = MODE_CLIENT;
        } else if (strcmp(argv[i], "--server") == 0) {
            cfg->mode = MODE_SERVER;
        } else if (strcmp(argv[i], "--vpn") == 0) {
            cfg->vpn_enabled = 1;
        } else if (strcmp(argv[i], "--no-vpn") == 0) {
            cfg->vpn_enabled = 0;
        } else if (strcmp(argv[i], "--no-route") == 0) {
            cfg->route_all = 0;
        } else if (strcmp(argv[i], "--ipv6") == 0) {
            cfg->ipv6_enabled = 1;
        } else if (strcmp(argv[i], "--no-ipv6") == 0) {
            cfg->ipv6_enabled = 0;
        } else if (strcmp(argv[i], "--no-dns") == 0) {
            cfg->dns_enabled = 0;
        } else if (strcmp(argv[i], "--dns-server") == 0 && i + 1 < argc) {
            copy_text(cfg->dns_server, sizeof(cfg->dns_server), argv[++i]);
            cfg->dns_enabled = 1;
        } else if (strcmp(argv[i], "--dns-tunnel-domain") == 0 && i + 1 < argc) {
            copy_text(cfg->dns_tunnel_domain, sizeof(cfg->dns_tunnel_domain), argv[++i]);
            normalize_domain(cfg->dns_tunnel_domain);
        } else if ((strcmp(argv[i], "--dns-resolver") == 0 ||
                    strcmp(argv[i], "--dns-tunnel-resolver") == 0) && i + 1 < argc) {
            copy_text(cfg->dns_tunnel_resolver, sizeof(cfg->dns_tunnel_resolver), argv[++i]);
        } else if (strcmp(argv[i], "--tun-name") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_name, sizeof(cfg->tun_name), argv[++i]);
        } else if (strcmp(argv[i], "--tun-server-ip") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_server_ip, sizeof(cfg->tun_server_ip), argv[++i]);
        } else if (strcmp(argv[i], "--tun-client-ip") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_client_ip, sizeof(cfg->tun_client_ip), argv[++i]);
        } else if (strcmp(argv[i], "--tun-cidr") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_cidr, sizeof(cfg->tun_cidr), argv[++i]);
        } else if (strcmp(argv[i], "--tun-server-ip6") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_server_ip6, sizeof(cfg->tun_server_ip6), argv[++i]);
        } else if (strcmp(argv[i], "--tun-client-ip6") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_client_ip6, sizeof(cfg->tun_client_ip6), argv[++i]);
        } else if (strcmp(argv[i], "--tun-cidr6") == 0 && i + 1 < argc) {
            copy_text(cfg->tun_cidr6, sizeof(cfg->tun_cidr6), argv[++i]);
        } else if (strcmp(argv[i], "--tun-mtu") == 0 && i + 1 < argc) {
            cfg->tun_mtu = atoi(argv[++i]);
            if (cfg->tun_mtu < 576 || cfg->tun_mtu > ST_MAX_PAYLOAD) {
                fprintf(stderr, "invalid tunnel MTU\n");
                return -1;
            }
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
        maybe_pause_on_windows_error(&cfg);
        return 2;
    }
    if (!cfg.tui) {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
#ifdef _WIN32
        SetUnhandledExceptionFilter(windows_crash_filter);
#endif
        printf("phase=main\n");
        fflush(stdout);
    }

    if (network_init() != 0) {
        fprintf(stderr, "error: network initialization failed\n");
        maybe_pause_on_windows_error(&cfg);
        return 1;
    }
    if (!cfg.tui) {
        printf("phase=network_ready\n");
        fflush(stdout);
    }

    rc = cfg.tui ? run_tui(cfg) : run_headless(cfg);
    network_cleanup();
    return rc;
}
