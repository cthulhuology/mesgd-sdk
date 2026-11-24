/*
 * mesgd-sdk C Ping/Pong Sample
 * =============================
 * Demonstrates the full mesgd-sdk lifecycle in C:
 *   1. Initialise local PKI keys (OpenSSL EVP)
 *   2. Register our public keys with the mesgd echo server
 *   3. Open a WebSocket connection (libwebsockets)
 *   4. Send 3 signed+encrypted "ping" messages
 *   5. Receive and verify the echoed "pong" response each time
 *
 * Build:  make
 * Run:    ./sample
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SDK headers — relative to the SDK root */
#include "../../pki.h"    /* pki_init, pki_sign, pki_encrypt_with, pki_register, ... */
#include "../../mesgd.h"  /* mesgd_connect, mesgd_send, mesgd_receive, mesgd_disconnect */

/* JSON for loading mesgd_pub.json */
#include <cjson/cJSON.h>

#define DEFAULT_MESGD_URL     "wss://echo.mesgd.org/ws"
#define DEFAULT_PUB_JWK_PATH  "mesgd_pub.json"
#define ROUNDS                3

/* Read an entire file into a heap-allocated string. Caller must free(). */
static char *read_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(fp); return NULL; }
    fread(buf, 1, (size_t)len, fp);
    buf[len] = '\0';
    fclose(fp);
    return buf;
}

int main(void) {
    printf("=== mesgd-sdk C Ping/Pong Sample ===\n\n");

    /* Configuration from environment (fall back to defaults) */
    const char *mesgd_url      = getenv("MESGD_URL")     ? getenv("MESGD_URL")     : DEFAULT_MESGD_URL;
    const char *pub_jwk_path   = getenv("MESGD_PUB_JWK") ? getenv("MESGD_PUB_JWK") : DEFAULT_PUB_JWK_PATH;

    /* ------------------------------------------------------------------
     * Step 1: Initialise PKI
     *   Loads pki_keys.json or generates a fresh ECDSA P-256 + RSA-2048
     *   key pair and writes pki_keys.json.
     * ------------------------------------------------------------------ */
    printf("Step 1: Initialising PKI ...\n");
    if (pki_init() != 0) {
        fprintf(stderr, "ERROR: pki_init() failed\n");
        return 1;
    }
    printf("        Keys ready.\n\n");

    /* ------------------------------------------------------------------
     * Step 2: Load mesgd's public encryption key from JSON file
     * ------------------------------------------------------------------ */
    printf("Step 2: Loading mesgd public key from '%s' ...\n", pub_jwk_path);
    char *pub_jwk_json = read_file(pub_jwk_path);
    if (!pub_jwk_json) {
        fprintf(stderr, "ERROR: Cannot read '%s'.\n", pub_jwk_path);
        fprintf(stderr, "  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json\n");
        return 1;
    }
    cJSON *mesgd_pub_jwk = cJSON_Parse(pub_jwk_json);
    free(pub_jwk_json);
    if (!mesgd_pub_jwk) {
        fprintf(stderr, "ERROR: '%s' is not valid JSON.\n", pub_jwk_path);
        return 1;
    }
    printf("        Loaded.\n\n");

    /* ------------------------------------------------------------------
     * Step 3: Register with mesgd
     *   Assembles our public keys, signs with signing_priv, encrypts
     *   with mesgd's encrypting_pub, returns a base64 ciphertext.
     * ------------------------------------------------------------------ */
    printf("Step 3: Registering with mesgd ...\n");
    char *registration_ct = pki_register(mesgd_pub_jwk);
    if (!registration_ct) {
        fprintf(stderr, "ERROR: pki_register() failed\n");
        cJSON_Delete(mesgd_pub_jwk);
        return 1;
    }
    printf("        Registration payload (first 40 chars): %.40s...\n\n", registration_ct);

    /* ------------------------------------------------------------------
     * Step 4: Connect WebSocket
     * ------------------------------------------------------------------ */
    printf("Step 4: Connecting to %s ...\n", mesgd_url);
    MesgdConn *ws = mesgd_connect(mesgd_url, registration_ct);
    free(registration_ct);
    if (!ws) {
        fprintf(stderr, "ERROR: mesgd_connect() failed\n");
        cJSON_Delete(mesgd_pub_jwk);
        return 1;
    }
    printf("        Connected.\n\n");

    /* ------------------------------------------------------------------
     * Step 5: Ping / pong loop
     *   Each iteration signs+encrypts a message, sends it, receives the
     *   echo, decrypts+verifies, then asserts equality.
     * ------------------------------------------------------------------ */
    printf("Step 5: Starting %d-round ping/pong ...\n\n", ROUNDS);
    int success = 1;
    for (int i = 1; i <= ROUNDS; i++) {
        char message[128];
        snprintf(message, sizeof(message), "Hello from mesgd-sdk! C ping #%d", i);

        printf("  [%d/%d] Sending  : %s\n", i, ROUNDS, message);
        if (mesgd_send(ws, mesgd_pub_jwk, message) != 0) {
            fprintf(stderr, "ERROR: mesgd_send() failed on round %d\n", i);
            success = 0;
            break;
        }

        char *response = mesgd_receive(ws);
        if (!response) {
            fprintf(stderr, "ERROR: mesgd_receive() returned NULL on round %d\n", i);
            success = 0;
            break;
        }
        printf("  [%d/%d] Received : %s\n", i, ROUNDS, response);

        if (strcmp(response, message) != 0) {
            fprintf(stderr, "ERROR: Echo mismatch on round %d\n", i);
            fprintf(stderr, "  Expected: %s\n  Got:      %s\n", message, response);
            free(response);
            success = 0;
            break;
        }
        free(response);
        printf("  [%d/%d] Echo verified\n\n", i, ROUNDS);
    }

    mesgd_disconnect(ws);
    cJSON_Delete(mesgd_pub_jwk);
    printf("Connection closed.\n");

    if (success) {
        printf("\nAll %d ping/pong rounds passed.\n", ROUNDS);
        return 0;
    } else {
        return 1;
    }
}
