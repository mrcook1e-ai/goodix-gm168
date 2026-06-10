// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "goodix_proto.h"
#include <glib.h>
#include <openssl/ssl.h>
#include <pthread.h> /* for pthread_t */

typedef struct _GoodixGM168TlsServer GoodixGM168TlsServer;

typedef void (*GoodixGM168TlsConnectedCb)(GoodixGM168TlsServer *self,
                                           GError               *error,
                                           gpointer              user_data);

struct _GoodixGM168TlsServer {
    /* Callbacks */
    GoodixGM168TlsConnectedCb on_connected; /* called on handshake complete or error */
    gpointer                   user_data;

    /* OpenSSL */
    SSL_CTX  *ctx;
    SSL      *ssl;

    /*
     * Transport: socketpair(AF_UNIX, SOCK_STREAM)
     *
     *   sock_fd   -- passed to SSL_set_fd; the SSL thread reads/writes here
     *   client_fd -- driver uses: write() = feed MCU data in,
     *                             read()  = pull handshake response out
     *
     * Thread-safety rationale (no mutex needed):
     *   - During SSL_accept: SSL thread owns sock_fd; driver owns client_fd.
     *     These are different fds -- POSIX kernel buffers guarantee safe
     *     concurrent read/write on opposite ends of a socketpair.
     *   - After SSL_accept: tls_serve_thread exits.  SSL_read / SSL_write
     *     are called exclusively from the GLib main loop (single-threaded).
     */
    int sock_fd;
    int client_fd;

    /* Server thread handle (joined in deinit) */
    pthread_t thread;

    /* G9: cancel flag set by goodix_gm168_tls_cancel(). The serve thread
     * checks this after SSL_accept returns to distinguish "handshake
     * actually failed" from "deactivate cancelled us cleanly". Plain
     * volatile is enough — single writer (cancel), single reader (thread). */
    volatile gboolean cancel_requested;
};

// Initialize TLS server. Starts the handshake-wait thread.
// on_connected is called when the handshake completes (error=NULL) or fails (error!=NULL).
gboolean goodix_gm168_tls_init    (GoodixGM168TlsServer *self, GError **error);

// Feed raw TLS bytes from the MCU (from a B0 packet) into OpenSSL.
int      goodix_gm168_tls_feed    (GoodixGM168TlsServer *self, const guint8 *data,
                                    guint32 length);

// Pull TLS bytes that OpenSSL wants to send to the MCU (wrap in B0 and send).
int      goodix_gm168_tls_pull    (GoodixGM168TlsServer *self, guint8 *buf,
                                    guint16 size);

// Read decrypted data from the MCU (after handshake completes).
int      goodix_gm168_tls_recv    (GoodixGM168TlsServer *self, guint8 *buf,
                                    guint32 size, GError **error);

// Encrypt and send data to the MCU.
int      goodix_gm168_tls_send    (GoodixGM168TlsServer *self, const guint8 *data,
                                    guint16 length);

// G9: Cancel any in-flight handshake/recv. Idempotent. Safe to call from any
// thread. After this returns, the serve thread will exit promptly and
// goodix_gm168_tls_deinit can finish without blocking.
void     goodix_gm168_tls_cancel  (GoodixGM168TlsServer *self);

// Tear down TLS state and join the serve thread.
void     goodix_gm168_tls_deinit  (GoodixGM168TlsServer *self);
