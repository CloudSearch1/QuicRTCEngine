#include"Xquic_Client.h"
#include"Xquic_Server.h"

static int get_last_sys_errno() {
    return errno;
}

static void set_last_sys_errno(int err_custom) {
    errno = err_custom;
}

static void usleep(unsigned long usec)
{
    HANDLE timer;
    LARGE_INTEGER interval;
    interval.QuadPart = -(10 * usec);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &interval, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}

#define XQC_MAX_TOKEN_LEN 256
#define XQC_ALPN_TRANSPORT "transport"
#define XQC_MAX_LOG_LEN  2048
#define XQC_PACKET_TMP_BUF_LEN 1500
static int g_drop_rate;
#define TEST_DROP (g_drop_rate != 0 && rand() % 1000 < g_drop_rate)
#define MAX_BUF_SIZE (100*1024*1024)
#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8898
#define MAX_HEADER 100
#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);
#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_SHORT_HEADER_PACKET_B "\x80\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

char g_headers[MAX_HEADER][256];
int g_header_cnt = 0;
int g_ping_id = 1;
int g_verify_cert = 0;
int g_verify_cert_allow_self_sign = 0;
int g_header_num = 6;
char g_header_key[MAX_HEADER_KEY_LEN];
char g_header_value[MAX_HEADER_VALUE_LEN];
int g_read_body;
char g_multi_interface[XQC_DEMO_MAX_PATH_COUNT][64];
char g_log_path[256];
int g_test_case;
uint64_t g_last_sock_op_time;
struct event_base* eb;
int g_send_body_size;
int g_send_body_size_defined;
char g_read_file[256] = "./test2.mp4";
int g_save_body;
char g_write_file[256];
int g_echo_check;
int g_is_get;
char g_scheme[8] = "https";
char g_host[64] = "test.xquic.com";
int g_conn_timeout = 1;
int g_ipv6;
static uint64_t last_recv_ts = 0;
unsigned char tmp_user_stream[2048];

typedef struct xqc_user_path_s {
    int                 path_fd;
    uint64_t            path_id;

    struct sockaddr* peer_addr;
    socklen_t           peer_addrlen;
    struct sockaddr* local_addr;
    socklen_t           local_addrlen;

    struct event* ev_socket;
} xqc_user_path_t;

typedef struct user_conn_s user_conn_t;
typedef struct user_stream_s {
    xqc_stream_t* stream;
    xqc_h3_request_t* h3_request;
    user_conn_t* user_conn;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char* send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char* recv_body;
    size_t              recv_body_len;
    FILE* recv_body_fp;
    int                 recv_fin;
    xqc_msec_t          start_time;
    xqc_msec_t          first_frame_time;   /* first frame download time */
    xqc_msec_t          last_read_time;
    int                 abnormal_count;
    int                 body_read_notify_cnt;
} user_stream_t;


typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr* local_addr;
    socklen_t           local_addrlen;
    xqc_flag_t          get_local_addr;
    struct sockaddr* peer_addr;
    socklen_t           peer_addrlen;

    unsigned char* token;
    unsigned            token_len;

    struct event* ev_socket;
    struct event* ev_timeout;

    int                 h3;

    int                 rebinding_fd;
    struct event* rebinding_ev_socket;
} user_conn_t;

typedef struct client_ctx_s {
    xqc_engine_t* engine;
    struct event* ev_engine;
    int             log_fd;
    int             keylog_fd;
    struct event* ev_delay;
} client_ctx_t;


xqc_user_path_t g_client_path[XQC_DEMO_MAX_PATH_COUNT];
int g_multi_interface_cnt = 0;
int hsk_completed = 0;

#define XQC_TEST_LONG_HEADER_LEN 32769
char test_long_value[XQC_TEST_LONG_HEADER_LEN] = { '\0' };

client_ctx_t ctx;

int xqc_client_open_keylog_file(client_ctx_t* ctx)
{
    ctx->keylog_fd = open("./ckeys.log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }
    return 0;
}

int xqc_client_open_log_file(void* engine_user_data)
{
    client_ctx_t* ctx = (client_ctx_t*)engine_user_data;
    ctx->log_fd = open(g_log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}


void xqc_client_set_event_timer(xqc_msec_t wake_after, void* user_data)
{
    client_ctx_t* ctx = (client_ctx_t*)user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

void xqc_client_write_log(xqc_log_level_t lvl, const void* buf, size_t count, void* engine_user_data)
{
    char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t* ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        //printf("xqc_client_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char*)buf);
    if (log_len < 0) {
        printf("xqc_client_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_last_sys_errno());
    }
}

void xqc_keylog_cb(const char* line, void* user_data)
{
    client_ctx_t* ctx = (client_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_last_sys_errno());
        return;
    }

    write_len = write(ctx->keylog_fd, "\n", 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_last_sys_errno());
    }
}

ssize_t xqc_client_write_socket(const unsigned char* buf, size_t size,
    const struct sockaddr* peer_addr, socklen_t peer_addrlen, void* user)
{
    user_conn_t* user_conn = (user_conn_t*)user;
    ssize_t res = 0;
    int fd = user_conn->fd;

    if (g_test_case == 41) {
        /* delay short header packet to make server idle timeout */
        if ((buf[0] & 0xC0) == 0x40) {
            Sleep(2);
            g_test_case = -1;
        }
    }

    if (g_test_case == 42 && hsk_completed == 1) {
        fd = user_conn->rebinding_fd;
    }

    /* COPY to run corruption test cases */
    char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;

    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_client_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* trigger version negotiation */
    if (g_test_case == 33) {
        /* makes version 0xff000001 */
        send_buf[1] = 0xff;
    }

    /* make initial packet loss to test 0rtt buffer */
    if (g_test_case == 39) {
        g_test_case = -1;
        return size;
    }

    do {
        set_last_sys_errno(0);

        g_last_sock_op_time = xqc_now();

        if (TEST_DROP) {
            return send_buf_size;
        }
        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            set_last_sys_errno(EAGAIN);
            return XQC_SOCKET_EAGAIN;
        }

        /* client Initial dcid corruption */
        if (g_test_case == 22) {
            /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[6] = ~send_buf[6];
            printf("test case 22, corrupt byte[6]\n");
        }

        /* client Initial scid corruption */
        if (g_test_case == 23) {
            /* bytes [15, 22] is the SCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[15] = ~send_buf[15];
            printf("test case 23, corrupt byte[15]\n");
        }

        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(get_last_sys_errno()));
            if (get_last_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_last_sys_errno() == EINTR));

    return res;
}

void xqc_client_save_token(const unsigned char* token, unsigned token_len, void* user_data)
{
    user_conn_t* user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    if (g_test_case == 16) { /* test application delay */
        usleep(300 * 1000);
    }
    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_last_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_last_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
}

int
xqc_client_cert_verify(const unsigned char* certs[],
    const size_t cert_len[], size_t certs_len, void* conn_user_data)
{
    /* self-signed cert used in test cases, return >= 0 means success */
    return 0;
}

void save_session_cb(const char* data, size_t data_len, void* user_data)
{
    user_conn_t* user_conn = (user_conn_t*)user_data;
    printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE* fp = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void
save_tp_cb(const char* data, size_t data_len, void* user_data)
{
    user_conn_t* user_conn = (user_conn_t*)user_data;
    printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE* fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

xqc_int_t
xqc_client_conn_closing_notify(xqc_connection_t* conn,
    const xqc_cid_t* cid, xqc_int_t err_code, void* conn_user_data)
{
    printf("conn closing: %d\n", err_code);
    return XQC_OK;
}

int xqc_client_conn_create_notify(xqc_connection_t* conn, const xqc_cid_t* cid, void* user_data, void* conn_proto_data)
{
    DEBUG;

    user_conn_t* user_conn = (user_conn_t*)user_data;
    xqc_conn_set_alp_user_data(conn, user_conn);

    printf("xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int xqc_client_conn_close_notify(xqc_connection_t* conn, const xqc_cid_t* cid, void* user_data, void* conn_proto_data)
{
    DEBUG;

    user_conn_t* user_conn = (user_conn_t*)conn_proto_data;

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%""llu"" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
        stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    event_base_loopbreak(eb);
    return 0;
}

static void xqc_client_engine_callback(int fd, short what, void* arg)
{
    printf("timer wakeup now:%""llu""\n", xqc_now());
    client_ctx_t* ctx = (client_ctx_t*)arg;

    xqc_engine_main_logic(ctx->engine);
}

void xqc_client_conn_handshake_finished(xqc_connection_t* conn, void* user_data, void* conn_proto_data)
{
    DEBUG;
    user_conn_t* user_conn = (user_conn_t*)user_data;
    xqc_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
    xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);

    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));
    printf("====>SCID:%s\n", xqc_scid_str(&user_conn->cid));

    hsk_completed = 1;
}

void xqc_client_conn_ping_acked_notify(xqc_connection_t* conn, const xqc_cid_t* cid, void* ping_user_data, void* user_data, void* conn_proto_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int*)ping_user_data);

    }
    else {
        printf("====>no ping_id\n");
    }
}


int read_file_data(char* data, size_t data_len, char* filename)
{
    int ret = 0;
    size_t total_len, read_len;
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0, SEEK_END);
    total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (total_len > data_len) {
        ret = -1;
        goto end;
    }

    read_len = fread(data, total_len, total_len, fp);
    if (read_len != total_len) {
        ret = -1;
        goto end;
    }

    ret = read_len;

end:
    if (fp) {
        fclose(fp);
    }
    return ret;
}

int xqc_client_stream_send(xqc_stream_t* stream, void* user_data)
{
    ssize_t ret;
    user_stream_t* user_stream = (user_stream_t*)user_data;

    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (g_read_body) {
            user_stream->send_body = (char *)malloc(user_stream->send_body_max);
        }
        else {
            user_stream->send_body = (char *)malloc(g_send_body_size);
            memset(user_stream->send_body, 1, g_send_body_size);
        }
        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        /* specified size > specified file > default size */
        if (g_send_body_size_defined) {
            user_stream->send_body_len = g_send_body_size;
        }
        else if (g_read_body) {
            ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
            if (ret < 0) {
                printf("read body error\n");
                return -1;
            }
            else {
                user_stream->send_body_len = ret;
            }
        }
        else {
            user_stream->send_body_len = g_send_body_size;
        }
    }

    int fin = 0;
    if (g_test_case == 4) { /* test fin_only */
        fin = 0;
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_stream_send(stream, (unsigned char*)user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;

        }
        else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%""llu""\n", user_stream->send_offset);
        }
    }

    if (g_test_case == 4) { /* test fin_only */
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200 * 1000);
            ret = xqc_stream_send(stream, (unsigned char *)user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_stream_send sent:%zd, offset=%""llu"", fin=1\n", ret, user_stream->send_offset);
        }
    }

    return 0;
}

int
xqc_client_stream_read_notify(xqc_stream_t* stream, void* user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t* user_stream = (user_stream_t*)user_data;
    char buff[4096] = { 0 };
    size_t buff_size = 4096;
    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    if (g_echo_check && user_stream->recv_body == NULL) {
        user_stream->recv_body = (char *)malloc(user_stream->send_body_len);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    ssize_t read;
    ssize_t read_sum = 0;

    do {
        read = xqc_stream_recv(stream, (unsigned char *)buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        }
        else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if (save) fflush(user_stream->recv_body_fp);

        /* write received body to memory */
        if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }

        read_sum += read;
        user_stream->recv_body_len += read;

    } while (read > 0 && !fin);

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    /* test first frame rendering time */
    if (g_test_case == 14 && user_stream->first_frame_time == 0 && user_stream->recv_body_len >= 98 * 1024) {
        user_stream->first_frame_time = xqc_now();
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        xqc_msec_t tmp = xqc_now();
        if (tmp - user_stream->last_read_time > 150 * 1000 && user_stream->last_read_time != 0) {
            user_stream->abnormal_count++;
            printf("\033[33m!!!!!!!!!!!!!!!!!!!!abnormal!!!!!!!!!!!!!!!!!!!!!!!!\033[0m\n");
        }
        user_stream->last_read_time = tmp;
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_msec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%""llu"" us, speed:%""llu"" K/s \n"
            ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
            now_us - user_stream->start_time,
            (user_stream->send_body_len + user_stream->recv_body_len) * 1000 / (now_us - user_stream->start_time),
            user_stream->send_body_len, user_stream->recv_body_len);

    }
    return 0;
}

int xqc_client_stream_write_notify(xqc_stream_t* stream, void* user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t* user_stream = (user_stream_t*)user_data;
    ret = xqc_client_stream_send(stream, user_stream);
    return ret;
}

int
xqc_client_stream_close_notify(xqc_stream_t* stream, void* user_data)
{
    DEBUG;
    user_stream_t* user_stream = (user_stream_t*)user_data;
    if (g_echo_check) {
        int pass = 0;
        printf("user_stream->recv_fin:%d, user_stream->send_body_len:%zu, user_stream->recv_body_len:%zd\n",
            user_stream->recv_fin, user_stream->send_body_len, user_stream->recv_body_len);
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
            pass = 1;
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    /* test first frame rendering time */
    if (g_test_case == 14) {
        printf("first_frame_time: %""llu"", start_time: %""llu""\n", user_stream->first_frame_time, user_stream->start_time);
        xqc_msec_t t = user_stream->first_frame_time - user_stream->start_time + 200000 /* server-side time consumption */;
        printf("\033[33m>>>>>>>> first_frame pass:%d time:%""llu""\033[0m\n", t <= 1000000 ? 1 : 0, t);
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        printf("\033[33m>>>>>>>> abnormal pass:%d count:%d\033[0m\n", user_stream->abnormal_count == 0 ? 1 : 0, user_stream->abnormal_count);
    }
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);
    return 0;
}

int xqc_client_read_token(unsigned char* token, unsigned token_len)
{
    int fd = open("./xqc_token", O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(get_last_sys_errno()));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    printf("read token size %zu\n", n);
    close(fd);
    return n;
}

static void
xqc_client_timeout_callback(int fd, short what, void* arg)
{
    printf("xqc_client_timeout_callback now %""llu""\n", xqc_now());
    user_conn_t* user_conn = (user_conn_t*)arg;
    int rc;
    static int restart_after_a_while = 1;

    //Test case 15: testing restart from idle
    if (restart_after_a_while && g_test_case == 15) {
        restart_after_a_while--;
        //we don't care the memory leak caused by user_stream. It's just for one-shot testing. :D
        user_stream_t* user_stream = (user_stream_t*)calloc(1, sizeof(user_stream_t));
        memset(user_stream, 0, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        printf("gtest 15: restart from idle!\n");
        user_stream->stream = xqc_stream_create(ctx.engine, &(user_conn->cid), user_stream);
        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            goto conn_close;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        printf("scheduled a new stream request\n");
        return;
    }

    if (xqc_now() - g_last_sock_op_time < (uint64_t)g_conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

conn_close:
    rc = xqc_conn_close(ctx.engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
    //event_base_loopbreak(eb);
}

void xqc_convert_addr_text_to_sockaddr(int type,
    const char* addr_text, unsigned int port,
    struct sockaddr** saddr, socklen_t* saddr_len)
{
    if (type == AF_INET6) {
        *saddr = (sockaddr*)calloc(1, sizeof(struct sockaddr_in6));
        memset(*saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)(*saddr);
        inet_pton(type, addr_text, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in6);

    }
    else {
        *saddr = (sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        memset(*saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in* addr_v4 = (struct sockaddr_in*)(*saddr);
        inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in);
    }
}

void xqc_client_init_addr(user_conn_t* user_conn,
    const char* server_addr, int server_port)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_convert_addr_text_to_sockaddr(ip_type,
        server_addr, server_port,
        &user_conn->peer_addr,
        &user_conn->peer_addrlen);

    if (ip_type == AF_INET6) {
        user_conn->local_addr = (struct sockaddr*)calloc(1, sizeof(struct sockaddr_in6));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in6));
        user_conn->local_addrlen = sizeof(struct sockaddr_in6);

    }
    else {
        user_conn->local_addr = (struct sockaddr*)calloc(1, sizeof(struct sockaddr_in));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in));
        user_conn->local_addrlen = sizeof(struct sockaddr_in);
    }
}

static int xqc_client_create_socket(int type,
    const struct sockaddr* saddr, socklen_t saddr_len)
{
    int size;
    int fd = -1;
    int flags;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_last_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, (u_long*) & flags) == SOCKET_ERROR) {
        goto err;
    }
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }
#endif

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    g_last_sock_op_time = xqc_now();

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr*)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }
#endif

    return fd;

err:
    close(fd);
    return -1;
}


void xqc_client_socket_write_handler(user_conn_t* user_conn)
{
    DEBUG
    xqc_conn_continue_send(ctx.engine, &user_conn->cid);
}

void xqc_client_socket_read_handler(user_conn_t* user_conn, int fd)
{
    //DEBUG;

    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;

    do {
        recv_size = recvfrom(fd,
            (char *)packet_buf, sizeof(packet_buf), 0,
            user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && get_last_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(get_last_sys_errno()));
            break;
        }

        /* if recv_size is 0, break while loop, */
        if (recv_size == 0) {
            break;
        }

        recv_sum += recv_size;
        rcv_sum += recv_size;

        if (user_conn->get_local_addr == 0) {
            user_conn->get_local_addr = 1;
            socklen_t tmp = sizeof(struct sockaddr_in6);
            int ret = getsockname(user_conn->fd, (struct sockaddr*)user_conn->local_addr, &tmp);
            if (ret < 0) {
                printf("getsockname error, errno: %d\n", get_last_sys_errno());
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();
        g_last_sock_op_time = recv_time;


        if (TEST_DROP) continue;

        if (g_test_case == 6) { /* socket recv fail */
            g_test_case = -1;
            break;
        }

        if (g_test_case == 8) { /* packet with wrong cid */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_A) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_A, recv_size);
        }

        static char copy[XQC_PACKET_TMP_BUF_LEN];

        if (g_test_case == 9) { /* duplicate packet */
            memcpy(copy, packet_buf, recv_size);
        again:;
        }

        if (g_test_case == 10) { /* illegal packet */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_B) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_B, recv_size);
        }

        /* amplification limit */
        if (g_test_case == 25) {
            static int loss_num = 0;
            loss_num++;
            /* continuous loss to make server at amplification limit */
            if (loss_num >= 1 && loss_num <= 10) {
                continue;
            }
        }

        if (xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
            user_conn->local_addr, user_conn->local_addrlen,
            user_conn->peer_addr, user_conn->peer_addrlen,
            (xqc_msec_t)recv_time, user_conn) != XQC_OK)
        {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }

        if (g_test_case == 9) { /* duplicate packet */
            g_test_case = -1;
            memcpy(packet_buf, copy, recv_size);
            goto again;
        }

    } while (recv_size > 0);

    if ((xqc_now() - last_recv_ts) > 200000) {
        printf("recving rate: %.3lf Kbps\n", (rcv_sum - last_rcv_sum) * 8.0 * 1000 / (xqc_now() - last_recv_ts));
        last_recv_ts = xqc_now();
        last_rcv_sum = rcv_sum;
    }

finish_recv:
    printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx.engine);
}


static void xqc_client_socket_event_callback(int fd, short what, void* arg)
{
    //DEBUG;
    user_conn_t* user_conn = (user_conn_t*)arg;

    if (what & EV_WRITE) {
        xqc_client_socket_write_handler(user_conn);

    }
    else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_conn, fd);

    }
    else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

user_conn_t* xqc_client_user_conn_create(const char* server_addr, int server_port,
    int transport)
{
    user_conn_t* user_conn = (user_conn_t*)calloc(1, sizeof(user_conn_t));

    /* use HTTP3? */
    user_conn->h3 = transport ? 0 : 1;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);

    user_conn->fd = xqc_client_create_socket(ip_type,
        user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return NULL;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST,
        xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);


    user_conn->rebinding_fd = xqc_client_create_socket(ip_type,
        user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->rebinding_fd < 0) {
        printf("|rebinding|xqc_create_socket error\n");
        return NULL;
    }

    user_conn->rebinding_ev_socket = event_new(eb, user_conn->rebinding_fd, EV_READ | EV_PERSIST,
        xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->rebinding_ev_socket, NULL);

    return user_conn;
}


int xqc_client_close_keylog_file(client_ctx_t* ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}

int xqc_client_close_log_file(void* engine_user_data)
{
    client_ctx_t* ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

void xqc_platform_init_env()
{
    int result = 0;

#ifdef XQC_SYS_WINDOWS  
    // Initialize Winsock
    WSADATA wsaData;
    if ((result = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) {
        printf("WSAStartup failed with error %d\n", result);
        exit(1);
    }
#endif

}



FILE* file_ptr;
int sum_file_size;
void OpenFile(char file[], FILE*& p)
{
    while (true)
    {
        if (!(p = fopen(file, "rb")))
        {
            memset(file, 0, sizeof(file));
            std::cout << "file path error" << std::endl;
        }
        else
        {
            break;
        }
    }
}

char* GetPilePath(char path[])
{
    static char name[20];
    memset(name, 0, sizeof(name));
    int len = strlen(path);
    int count = 0;
    for (int i = len - 1; i > 0; i--) {
        if (path[i] != '\\' && path[i] != '/') {
            count++;
        }
        else {
            break;
        }
    }
    int j = 0;
    int pos = len - count;
    for (int i = pos; i < len; i++) {
        name[j++] = path[i];
    }
    std::cout << "name£º" << name << std::endl;
    return name;
}


int main(int argc, char* argv[])
{
    int g_req_cnt = 0;
    int g_req_max = 1;
    int g_send_body_size = 1024 * 1024;
    int g_send_body_size_defined = 0;
    int g_save_body = 0;
    int g_read_body = 0;
    int g_echo_check = 0;
    int g_drop_rate = 0;
    int g_spec_url = 0;
    int g_is_get = 0;
    int g_test_case = 0;
    int g_ipv6 = 0;
    int g_no_crypt = 0;

    char server_addr[64] = TEST_SERVER_ADDR;
    int server_port = TEST_SERVER_PORT;
    int req_paral = 1;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    int transport = 1; // not use http 3
    int use_1rtt = 0;
    memset(g_header_key, 'k', sizeof(g_header_key));
    memset(g_header_value, 'v', sizeof(g_header_value));
    memset(&ctx, 0, sizeof(ctx));

    xqc_client_open_keylog_file(&ctx);
    xqc_client_open_log_file(&ctx);

    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    /* client does not need to fill in private_key_file & cert_file */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    if (g_test_case == 27) {
        engine_ssl_config.ciphers = "TLS_CHACHA20_POLY1305_SHA256";
    }

    xqc_engine_callback_t callback =
    {
        callback.set_event_timer = xqc_client_set_event_timer,
        callback.log_callbacks = {
            callback.log_callbacks.xqc_log_write_err = xqc_client_write_log,
            callback.log_callbacks.xqc_log_write_stat = xqc_client_write_log,
        },
        callback.cid_generate_cb = nullptr,
        callback.keylog_cb = xqc_keylog_cb
    };

    xqc_transport_callbacks_t tcbs =
    {
        tcbs.server_accept = nullptr,
        tcbs.server_refuse = nullptr,
        tcbs.stateless_reset = nullptr,
        tcbs.write_socket = xqc_client_write_socket,
        tcbs.write_mmsg = nullptr,
        tcbs.conn_update_cid_notify = nullptr,
        tcbs.save_token = xqc_client_save_token,
        tcbs.save_session_cb = save_session_cb,
        tcbs.save_tp_cb = save_tp_cb,
        tcbs.cert_verify_cb = xqc_client_cert_verify,
        tcbs.ready_to_create_path_notify = nullptr,
        tcbs.path_created_notify = nullptr,
        tcbs.path_removed_notify = nullptr,
        tcbs.conn_closing = xqc_client_conn_closing_notify,
        tcbs.conn_peer_addr_changed_notify = nullptr,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    cong_flags = XQC_BBR_FLAG_NONE;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
        }
#endif
    }
#ifndef XQC_DISABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
        cong_flags = XQC_BBR2_FLAG_NONE;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c, B, bbr+, bbr2+\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = 
    {
        conn_settings.pacing_on = pacing_on,
        conn_settings.ping_on = 0,
        conn_settings.cong_ctrl_callback = cong_ctrl,
        conn_settings.cc_params = 
        {
            conn_settings.cc_params.customize_on = 1,
            conn_settings.cc_params.init_cwnd = 32, 
            conn_settings.cc_params.cc_optimization_flags = cong_flags
        },
        conn_settings.proto_version = XQC_VERSION_V1,
        conn_settings.spurious_loss_detect_on = 0,
        conn_settings.keyupdate_pkt_threshold = 0,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    config.cfg_log_level = c_log_level == 'e' ? XQC_LOG_ERROR : (c_log_level == 'i' ? XQC_LOG_INFO : c_log_level == 'w' ? XQC_LOG_STATS : XQC_LOG_DEBUG);

    /* test different cid_len */
    if (g_test_case == 13) {
        config.cid_len = XQC_MAX_CID_LEN;
    }

    /* check draft-29 version */
    if (g_test_case == 17) {
        conn_settings.proto_version = XQC_IDRAFT_VER_29;
    }

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
    if (g_test_case == 20) { /* test sendmmsg */
        printf("test sendmmsg!\n");
        tcbs.write_mmsg = xqc_client_write_mmsg;
        config.sendmmsg_on = 1;
    }
#endif

    if (g_test_case == 24) {
        conn_settings.idle_time_out = 10000;
    }

    /* test spurious loss detect */
    if (g_test_case == 26) {
        conn_settings.spurious_loss_detect_on = 1;
    }

    /* test key update */
    if (g_test_case == 40) {
        conn_settings.keyupdate_pkt_threshold = 30;
    }

    if (g_test_case == 42) {
        conn_settings.max_pkt_out_size = 1400;
    }

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    ctx.keylog_fd;

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_config, &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        ap_cbs.conn_cbs = {
            ap_cbs.conn_cbs.conn_create_notify = xqc_client_conn_create_notify,
            ap_cbs.conn_cbs.conn_close_notify = xqc_client_conn_close_notify,
            ap_cbs.conn_cbs.conn_handshake_finished = xqc_client_conn_handshake_finished,
            ap_cbs.conn_cbs.conn_ping_acked = xqc_client_conn_ping_acked_notify,
        },
        ap_cbs.stream_cbs = {
            ap_cbs.stream_cbs.stream_write_notify = xqc_client_stream_write_notify,
            ap_cbs.stream_cbs.stream_read_notify = xqc_client_stream_read_notify,
            ap_cbs.stream_cbs.stream_close_notify = xqc_client_stream_close_notify,
        }
    };

    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);

    user_conn_t* user_conn = xqc_client_user_conn_create(server_addr, server_port, transport);
    if (user_conn == NULL) {
        printf("xqc_client_user_conn_create error\n");
        return -1;
    }

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);
    if (token_len > 0) {
        user_conn->token = token;
        user_conn->token_len = token_len;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    if (g_verify_cert) {
        conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_NEED_VERIFY;
        if (g_verify_cert_allow_self_sign) {
            conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        }
    }

    char session_ticket_data[8192] = { 0 };
    char tp_data[8192] = { 0 };

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;
    }
    else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }

    const xqc_cid_t* cid;
    cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,"127.0.0.1", g_no_crypt, &conn_ssl_config, user_conn->peer_addr,
        user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);

    if (cid == NULL) {
        printf("xqc_connect error\n");
        xqc_engine_destroy(ctx.engine);
        return 0;
    }

    /* copy cid to its own memory space to prevent crashes caused by internal cid being freed */
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    for (int i = 0; i < req_paral; i++) {
        g_req_cnt++;
        user_stream_t* user_stream = (user_stream_t*)calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;

        user_stream->stream = xqc_stream_create(ctx.engine, cid, user_stream);

        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            continue;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);

        int ret = 0;
        size_t total_len, read_len;
        FILE* fp = fopen("test.txt", "rb");

        fseek(fp, 0, SEEK_END);
        total_len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        int pre_send_length = 800;
        int index = 0;
        
        char buff[2048];

        while (total_len > 0)
        {
            if (pre_send_length > total_len)
            {
                pre_send_length = total_len;
            }
            read_len = fread(buff, 1, pre_send_length, fp);
            total_len -= pre_send_length;

            user_stream->send_body = buff;
            user_stream->send_body_len = pre_send_length;
            //user_stream->send_offset = 0;
            xqc_client_stream_send(user_stream->stream, user_stream);

            socklen_t peer_addrlen = 1;
            const struct sockaddr* perr_addr = (struct sockaddr*)"127.0.0.1";
            int fd = user_conn->fd;
            int res = sendto(fd, buff, pre_send_length, 0, user_conn->peer_addr, user_conn->peer_addrlen);
            std::cout << "res = " << res << std::endl;
        }
        fclose(fp);
    }

    
    last_recv_ts = xqc_now();
    event_base_dispatch(eb);

    event_free(user_conn->ev_socket);
    event_free(user_conn->ev_timeout);
    event_free(user_conn->rebinding_ev_socket);

    free(user_conn->peer_addr);
    free(user_conn->local_addr);
    free(user_conn);

    if (ctx.ev_delay) {
        event_free(ctx.ev_delay);
    }

    xqc_engine_destroy(ctx.engine);
    xqc_client_close_keylog_file(&ctx);
    xqc_client_close_log_file(&ctx);


    return 0;
}