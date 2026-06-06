/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Goodix GM168 -- OpenSSL TLS-PSK server
 *
 * Fix log (vs initial):
 *   [FIX-1] O_NONBLOCK on client_fd -- tls_pull never blocks the main thread
 *   [FIX-2] Correct order in TLS loop: USB read -> feed -> spinloop pull
 *   [FIX-3] Explicit pthread_join in deinit -- no thread leak
 *   [FIX-4] No mutex needed: SSL thread and driver thread use *different* fds
 *           of the socketpair; after SSL_accept the thread exits, so
 *           SSL_read/SSL_write run single-threaded from the GLib main loop.
 *   [G9-A]  SO_RCVTIMEO on sock_fd: SSL_accept can't hang forever even if
 *           the driver dies between TLS_START and the first handshake feed.
 *           Addresses AUDIT C2.
 *   [G9-B]  cancel_requested + shutdown(sock_fd): dev_deactivate can unblock
 *           a stuck SSL_accept immediately instead of waiting for the next
 *           dev_activate to tear down the thread. Addresses AUDIT C1.
 *   [G9-C]  SSL_read busy-loop shrunk from 50x5ms (250ms blocking main
 *           thread) to 5x1ms (5ms). Addresses AUDIT H10.
 */

#define FP_COMPONENT "goodix_gm168"

#include "goodix_tls.h"
#include "goodix_proto.h"
#include "drivers_api.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>      /* nanosleep */
#include <unistd.h>

// ─── Internal helpers ─────────────────────────────────────────────────────────

static GError *
err_from_ssl (void)
{
    // Drain the WHOLE OpenSSL error queue, not just the first error —
    // PSK / cipher failures usually surface as a stack (e.g. "bad
    // record mac" + "cipher operation failed"). The first-only path
    // hides the root cause.
    GString *all = g_string_new (NULL);
    unsigned long first_code = 0;
    unsigned long code;
    char buf[256];
    int  count = 0;

    while ((code = ERR_get_error ()) != 0) {
        if (first_code == 0)
            first_code = code;
        ERR_error_string_n (code, buf, sizeof (buf));
        if (count > 0)
            g_string_append (all, " | ");
        g_string_append (all, buf);
        count++;
    }
    if (count == 0)
        g_string_assign (all, "unknown SSL error (queue empty)");
    fp_warn ("goodix-gm168: OpenSSL error queue (%d entries): %s",
             count, all->str);
    GError *err = g_error_new_literal (G_FILE_ERROR, (gint)first_code, all->str);
    g_string_free (all, TRUE);
    return err;
}

// ─── PSK callback ─────────────────────────────────────────────────────────────
//
// MCU (клиент) присылает identity="Client_identity" и ждёт наш PSK.
static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *psk,
               unsigned int max_psk_len)
{
    (void)ssl;
    (void)identity;  /* MCU always sends "Client_identity" */

    g_debug ("goodix-gm168: PSK callback called, identity='%s', max_psk_len=%u",
             identity ? identity : "(null)", max_psk_len);

    /*
     * Используем REAL_PSK (goodix_gm168_psk) — 32-байтовый ключ,
     * захваченный через Frida из Windows-драйвера (Wbdi.dll).
     * MCU уже знает этот ключ — он был записан туда Windows-драйвером.
     * PSK запись/сброс требует TLS (или IAP-режим), поэтому мы не
     * можем сменить его до установки TLS-сессии.
     */
    unsigned int psk_len = (unsigned int)sizeof (goodix_gm168_psk);

    if (psk_len > max_psk_len) {
        g_warning ("goodix-gm168: PSK (%u B) > max_psk_len (%u B)",
                   psk_len, max_psk_len);
        return 0;
    }

    memcpy (psk, goodix_gm168_psk, psk_len);
    g_debug ("goodix-gm168: PSK callback returning %u bytes of REAL_PSK", psk_len);
    return psk_len;
}

// ─── SSL context setup ────────────────────────────────────────────────────────

static SSL_CTX *
create_ctx (void)
{
    SSL_CTX *ctx = SSL_CTX_new (TLS_server_method ());
    if (!ctx)
        return NULL;

    // TLS 1.2 only — именно эту версию использует GM168 (из Binary Ninja)
    SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);

    // OpenSSL 3.0+ default security level is 2, which rejects PSK-CBC
    // suites as "legacy". The sensor only speaks PSK-AES128-CBC-SHA256,
    // so we must drop the level. SECLEVEL=0 permits everything (we
    // control the cipher list above, so this is safe).
    SSL_CTX_set_security_level (ctx, 0);

    // The GM168 firmware predates RFC 7627 (Extended Master Secret) and
    // RFC 5746 (secure renegotiation). OpenSSL 3.0+ defaults to enforcing
    // EMS and refusing legacy renegotiation, which derives different
    // master-secret keys than the sensor expects and surfaces as
    // "decryption failed or bad record mac" on the very first Finished.
    // Disable both — confirmed-correct PSK + legacy KDF matches the MCU.
    SSL_CTX_set_options (ctx,
                         SSL_OP_NO_EXTENDED_MASTER_SECRET |
                         SSL_OP_LEGACY_SERVER_CONNECT |
                         SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

    // КРИТИЧНО: CBC-SHA256, НЕ GCM!
    if (SSL_CTX_set_cipher_list (ctx, GOODIX_GM168_TLS_CIPHER) != 1) {
        g_warning ("goodix-gm168: failed to set cipher list: %s",
                   GOODIX_GM168_TLS_CIPHER);
        SSL_CTX_free (ctx);
        return NULL;
    }

    SSL_CTX_set_psk_server_callback (ctx, psk_server_cb);
    return ctx;
}

// ─── TLS server thread ────────────────────────────────────────────────────────
//
// [FIX-2] Поток блокируется внутри SSL_accept.
// Данные поступают через socketpair:
//   driver → write(client_fd) → kernel → SSL thread reads from sock_fd
//   SSL thread writes to sock_fd → kernel → driver reads from client_fd
// Это полностью thread-safe: write/read на РАЗНЫХ fd socketpair.
// Mutex нужен только для защиты нескольких операций feed+pull как атомарного блока.

static void *
tls_serve_thread (void *arg)
{
    GoodixGM168TlsServer *self = arg;

    g_debug ("goodix-gm168: TLS server thread: SSL_accept...");
    int ret = SSL_accept (self->ssl);

    if (ret <= 0) {
        /* [G9-B] If the failure is because dev_deactivate called us with
         * tls_cancel(), don't fire on_connected with a confusing OpenSSL
         * error — the driver is already shutting down. Just exit quietly. */
        if (self->cancel_requested) {
            g_debug ("goodix-gm168: TLS handshake cancelled by deactivate");
            return NULL;
        }
        GError *err = err_from_ssl ();
        g_warning ("goodix-gm168: SSL_accept failed: %s", err->message);
        if (self->on_connected)
            self->on_connected (self, err, self->user_data);
        g_error_free (err);
    } else {
        g_debug ("goodix-gm168: TLS handshake COMPLETE ✓");
        
        /* 
         * [FIX-1.1] NOW set sock_fd to O_NONBLOCK so that subsequent SSL_read
         * calls in the main thread (during CAP_PROCESS) don't deadlock if a
         * TLS record is incomplete!
         */
        int flags = fcntl (self->sock_fd, F_GETFL, 0);
        if (flags >= 0) fcntl (self->sock_fd, F_SETFL, flags | O_NONBLOCK);

        if (self->on_connected)
            self->on_connected (self, NULL, self->user_data);
    }

    return NULL;
}

// ─── Public API ───────────────────────────────────────────────────────────────

gboolean
goodix_gm168_tls_init (GoodixGM168TlsServer *self, GError **error)
{
    g_assert (self);
    g_assert (self->on_connected);

    // Init OpenSSL
    SSL_load_error_strings ();
    OpenSSL_add_ssl_algorithms ();

    self->ctx = create_ctx ();
    if (!self->ctx) {
        g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                     "goodix-gm168: failed to create SSL context");
        return FALSE;
    }

    // socketpair: sock_fd ↔ client_fd
    int fds[2];
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        g_set_error (error, G_FILE_ERROR, errno,
                     "goodix-gm168: socketpair failed: %s", strerror (errno));
        SSL_CTX_free (self->ctx);
        self->ctx = NULL;
        return FALSE;
    }
    self->sock_fd   = fds[0];
    self->client_fd = fds[1];

    /*
     * [FIX-1] client_fd: set O_NONBLOCK so tls_pull() never stalls the main
     * thread when OpenSSL has not produced output yet (returns EAGAIN instead).
     * sock_fd remains blocking during SSL_accept, and will be switched to
     * non-blocking afterwards.
     */
    {
        int flags = fcntl (self->client_fd, F_GETFL, 0);
        if (flags >= 0) fcntl (self->client_fd, F_SETFL, flags | O_NONBLOCK);
    }

    /* Create SSL object and bind to sock_fd */
    self->ssl = SSL_new (self->ctx);
    if (!self->ssl) {
        g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                     "goodix-gm168: SSL_new failed");
        close (self->sock_fd);
        close (self->client_fd);
        SSL_CTX_free (self->ctx);
        return FALSE;
    }
    SSL_set_fd (self->ssl, self->sock_fd);

    /* [G9-A] Bound SSL_accept by giving the underlying recv() a wall-clock
     * cap. If the driver stops feeding handshake bytes mid-flow, recv()
     * returns EAGAIN after this timeout; the serve thread treats that as
     * "handshake hung" and exits with an error instead of hanging
     * indefinitely. 5 seconds is ~100x the observed handshake time
     * (~50 ms total, ~13 ms for the busiest step in our trace data). */
    {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        if (setsockopt (self->sock_fd, SOL_SOCKET, SO_RCVTIMEO,
                        &tv, sizeof (tv)) != 0) {
            g_warning ("goodix-gm168: SO_RCVTIMEO on sock_fd failed: %s",
                       strerror (errno));
            /* Non-fatal: cancel via shutdown() still works. */
        }
    }

    self->cancel_requested = FALSE;

    pthread_create (&self->thread, NULL, tls_serve_thread, self);
    return TRUE;
}

// Передать сырые TLS-байты от MCU (из B0/B2 пакета) в OpenSSL
// Thread-safe: write на client_fd, SSL thread читает из sock_fd (другой конец).
// Mutex не нужен для write vs read на разных fd — POSIX гарантирует atomicity.
int
goodix_gm168_tls_feed (GoodixGM168TlsServer *self, const guint8 *data,
                        guint32 length)
{
    ssize_t written = write (self->client_fd, data, length);
    if (written < 0) {
        g_printerr("goodix-gm168: tls_feed write error: %s (errno=%d)\n", strerror(errno), errno);
    } else if ((guint32)written != length) {
        g_printerr("goodix-gm168: tls_feed short write: %zd / %u\n", written, length);
    } else {
        fp_dbg("goodix-gm168: tls_feed wrote %zd bytes to client_fd", written);
    }
    return (int)written;
}

// Забрать TLS байты которые OpenSSL хочет отправить MCU
// [FIX-1] O_NONBLOCK: возвращает -1/EAGAIN если данных нет (не блокирует).
// Вызывать в цикле after sleep(1-5ms) пока не получим данные или таймаут.
int
goodix_gm168_tls_pull (GoodixGM168TlsServer *self, guint8 *buf, guint16 size)
{
    ssize_t n = read (self->client_fd, buf, size);
    /* На Linux EAGAIN == EWOULDBLOCK (оба == 11), проверяем только EAGAIN */
    if (n < 0 && errno == EAGAIN)
        return 0;   // нет данных — не ошибка
    return (int)n;
}

// Прочитать расшифрованные данные от MCU (после успешного handshake)
// Вызывается ТОЛЬКО после goodix_gm168_tls_feed.
int
goodix_gm168_tls_recv (GoodixGM168TlsServer *self, guint8 *buf, guint32 size,
                        GError **error)
{
    /*
     * [FIX-B1] SSL_read может вернуть SSL_ERROR_WANT_READ сразу после
     * goodix_gm168_tls_feed(), потому что данные ещё не успели пройти
     * через socketpair в OpenSSL-слой.
     *
     * [G9-C] Shrunk from 50x5ms (250ms blocking the main thread) to
     * 5x1ms (5ms cap). On WANT_READ after the cap, return 0 — the caller
     * loops back through CAP_RX which fetches more bytes from USB and
     * calls us again. Socketpair latency is <1ms in practice, so 5x1ms
     * still covers the legitimate case with margin.
     */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  /* 1 ms */
    for (int attempt = 0; attempt < 5; attempt++) {
        int ret = SSL_read (self->ssl, buf, (int)size);
        if (ret > 0)
            return ret;
        int ssl_err = SSL_get_error (self->ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ) {
            nanosleep (&ts, NULL);
            continue;
        }
        if (ssl_err == SSL_ERROR_ZERO_RETURN)
            return 0;

        /* Print full OpenSSL error stack to stderr for debugging */
        if (ssl_err != SSL_ERROR_NONE && ssl_err != SSL_ERROR_WANT_READ) {
            g_printerr("goodix-gm168: SSL_read failed, ssl_err=%d\n", ssl_err);
            unsigned long open_err;
            while ((open_err = ERR_get_error()) != 0) {
                g_printerr("goodix-gm168: OpenSSL error: %s\n", ERR_error_string(open_err, NULL));
            }
        }

        if (error)
            *error = err_from_ssl ();
        return ret;
    }
    
    // WANT_READ timeout — let the caller fetch more bytes and retry.
    return 0;
}

void
goodix_gm168_tls_cancel (GoodixGM168TlsServer *self)
{
    if (!self) return;
    if (self->cancel_requested) return; /* idempotent */
    self->cancel_requested = TRUE;
    /* shutdown() on sock_fd unblocks any pending recv() in the SSL thread
     * immediately — SSL_accept returns -1, we honour cancel_requested in
     * the serve thread. close() in deinit then completes the teardown.   */
    if (self->sock_fd >= 0) {
        shutdown (self->sock_fd, SHUT_RDWR);
    }
}

// Отправить данные MCU (зашифрует и запишет в sock_fd)
int
goodix_gm168_tls_send (GoodixGM168TlsServer *self, const guint8 *data,
                        guint16 length)
{
    return SSL_write (self->ssl, data, length);
}

void
goodix_gm168_tls_deinit (GoodixGM168TlsServer *self)
{
    if (!self)
        return;

    /* G9: belt-and-braces — even if dev_deactivate didn't call tls_cancel
     * (e.g. dev_close path), shutdown unblocks SSL_accept before close. */
    if (self->sock_fd >= 0) {
        shutdown (self->sock_fd, SHUT_RDWR);
    }

    /* Close sock_fd first -- this unblocks SSL_accept in the thread */
    if (self->sock_fd >= 0) {
        close (self->sock_fd);
        self->sock_fd = -1;
    }

    /* Wait for thread to finish (no zombie, no resource leak) */
    if (self->thread)
        pthread_join (self->thread, NULL);

    if (self->ssl) {
        SSL_free (self->ssl);
        self->ssl = NULL;
    }
    if (self->client_fd >= 0) {
        close (self->client_fd);
        self->client_fd = -1;
    }
    if (self->ctx) {
        SSL_CTX_free (self->ctx);
        self->ctx = NULL;
    }
}
