#include "mesgd.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* pki is used by textual inclusion elsewhere in this SDK; declare what we call. */
extern char *pki_sign(const char *message);
extern char *pki_seal(const char *pub_jwk_json, const char *plain);
extern char *pki_open(const char *sealed_json);

/* Build the wire frame. For sign/seal the message must carry a "body"; this
 * attaches "sig" over the body and swaps "body" for an encrypted "enc", leaving
 * the routable top-level fields visible so mesgd can still route. */
static char *frame(cJSON *message, mesgd_opts opts, const char *server_pub) {
    if (!opts.sign && !opts.seal) return cJSON_PrintUnformatted(message);
    char *body = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(message, "body"));
    if (opts.sign) {
        char *sig = pki_sign(body);
        cJSON_AddStringToObject(message, "sig", sig);
        free(sig);
    }
    if (opts.seal) {
        char *enc = pki_seal(server_pub, body);
        cJSON_DeleteItemFromObjectCaseSensitive(message, "body");
        cJSON_AddStringToObject(message, "enc", enc);
        free(enc);
    }
    free(body);
    return cJSON_PrintUnformatted(message);
}

static void dispatch(const char *raw, mesgd_handler handler, void *ctx) {
    cJSON *message = cJSON_Parse(raw);
    cJSON *enc = cJSON_GetObjectItemCaseSensitive(message, "enc");
    if (cJSON_IsString(enc)) {
        char *opened = pki_open(enc->valuestring);
        cJSON_DeleteItemFromObjectCaseSensitive(message, "enc");
        cJSON_AddItemToObject(message, "body", cJSON_Parse(opened));
        free(opened);
    }
    if (handler) handler(message, ctx);
    cJSON_Delete(message);
}

int mesgd_connect(mesgd *m, const char *url, const char *token, const char *server_pub) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char proto[4096];
    if (token) snprintf(proto, sizeof proto, "Sec-WebSocket-Protocol: json, %s", token);
    else       snprintf(proto, sizeof proto, "Sec-WebSocket-Protocol: json");
    struct curl_slist *headers = curl_slist_append(NULL, proto);

    const char *ca = getenv("MESGD_CA");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);   /* 2 == websocket */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (ca) curl_easy_setopt(curl, CURLOPT_CAINFO, ca);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK) { curl_easy_cleanup(curl); return -2; }

    m->curl = curl;
    m->server_pub = server_pub;
    m->handler = NULL;
    m->ctx = NULL;
    return 0;
}

void mesgd_on(mesgd *m, mesgd_handler handler, void *ctx) {
    m->handler = handler;
    m->ctx = ctx;
}

int mesgd_send(mesgd *m, cJSON *message, mesgd_opts opts) {
    char *wire = frame(message, opts, m->server_pub);
    size_t sent = 0;
    CURLcode rc = curl_ws_send(m->curl, wire, strlen(wire), &sent, 0, CURLWS_TEXT);
    free(wire);
    return rc == CURLE_OK ? 0 : -1;
}

int mesgd_recv(mesgd *m) {
    char buffer[65536];
    size_t got = 0;
    const struct curl_ws_frame *meta;
    CURLcode rc = curl_ws_recv(m->curl, buffer, sizeof buffer - 1, &got, &meta);
    if (rc != CURLE_OK) return -1;
    buffer[got] = '\0';
    dispatch(buffer, m->handler, m->ctx);
    return 0;
}

void mesgd_close(mesgd *m) {
    curl_easy_cleanup(m->curl);
    m->curl = NULL;
}
