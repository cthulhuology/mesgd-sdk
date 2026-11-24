/*
 * mesgd.h — mesgd transport client (libcurl WebSocket)
 *
 * One mesgd == one wss connection == one path == one JWT; open several for
 * several topics or grants. Keys come from pki_init()/pki_generate() first —
 * the connection is transport only, using the process-global PKI identity.
 * Security is opt-in: plain, signed (sig over body), or signed + sealed (body
 * encrypted, routable fields left in cleartext).
 */
#ifndef MESGD_H
#define MESGD_H

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mesgd_handler)(cJSON *message, void *ctx);

typedef struct {
    void          *curl;        /* CURL* kept open with CONNECT_ONLY websocket */
    const char    *server_pub;  /* encrypting_pub JWK (borrowed); NULL disables seal */
    mesgd_handler  handler;
    void          *ctx;
} mesgd;

typedef struct { int sign; int seal; } mesgd_opts;

/* url is wss://host/path (path = subscription). token and server_pub may be
 * NULL. Reads MESGD_CA for a private-CA bundle. Returns 0 on success. Call
 * curl_global_init(CURL_GLOBAL_DEFAULT) once before concurrent use. */
int  mesgd_connect(mesgd *m, const char *url, const char *token, const char *server_pub);

void mesgd_on(mesgd *m, mesgd_handler handler, void *ctx);

/* Publishes message as one text frame. message must carry a "body" sub-object
 * when sign/seal is set; mesgd_send mutates it in place (adds "sig", swaps
 * "body" for the encrypted "enc"). Returns 0 on success. */
int  mesgd_send(mesgd *m, cJSON *message, mesgd_opts opts);

/* Reads one text frame, decodes (opening "enc" back into "body"), dispatches to
 * the handler. Returns 0 on success. */
int  mesgd_recv(mesgd *m);

void mesgd_close(mesgd *m);

#ifdef __cplusplus
}
#endif
#endif
