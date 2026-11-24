/*
 * test_mesgd_ws.c — transport framing tests (no server): plain / signed / sealed
 * frame building and decode+dispatch, exercising the pki seal/open path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "pki.c"
#include "mesgd.c"

#define JWKS "../fixtures/jwks.json"

static cJSON *captured = NULL;
static void on_msg(cJSON *message, void *ctx) { (void)ctx; captured = cJSON_Duplicate(message, 1); }

void setUp(void) { pki_free(); captured = NULL; }
void tearDown(void) { pki_free(); cJSON_Delete(captured); captured = NULL; }

void test_plain_frame(void) {
    cJSON *m = cJSON_Parse("{\"to\":\"x/y\",\"type\":\"ping\",\"body\":{\"a\":1}}");
    char *wire = frame(m, (mesgd_opts){0, 0}, NULL);
    cJSON *w = cJSON_Parse(wire);
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItem(w, "body"));
    TEST_ASSERT_NULL(cJSON_GetObjectItem(w, "enc"));
    TEST_ASSERT_NULL(cJSON_GetObjectItem(w, "sig"));
    cJSON_Delete(w); free(wire); cJSON_Delete(m);
}

void test_signed_sealed_roundtrip(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS));
    char *pub = pki_pub_jwk();
    cJSON *m = cJSON_Parse("{\"to\":\"agents/alice/inbox\",\"type\":\"task.request\","
                           "\"body\":{\"cap\":\"summarize\",\"n\":3}}");
    char *wire = frame(m, (mesgd_opts){1, 1}, pub);

    cJSON *w = cJSON_Parse(wire);
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItem(w, "enc"));                              /* sealed */
    TEST_ASSERT_NULL(cJSON_GetObjectItem(w, "body"));                                /* body hidden */
    TEST_ASSERT_EQUAL_STRING("agents/alice/inbox",
        cJSON_GetStringValue(cJSON_GetObjectItem(w, "to")));                         /* routable cleartext */
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItem(w, "sig"));
    cJSON_Delete(w);

    dispatch(wire, on_msg, NULL);                                                     /* opens enc -> body */
    TEST_ASSERT_NOT_NULL(captured);
    TEST_ASSERT_EQUAL_STRING("task.request",
        cJSON_GetStringValue(cJSON_GetObjectItem(captured, "type")));
    cJSON *body = cJSON_GetObjectItem(captured, "body");
    TEST_ASSERT_EQUAL_STRING("summarize", cJSON_GetStringValue(cJSON_GetObjectItem(body, "cap")));

    const char *sig = cJSON_GetStringValue(cJSON_GetObjectItem(captured, "sig"));
    char *body_json = cJSON_PrintUnformatted(body);
    TEST_ASSERT_EQUAL_INT(1, pki_check_with_pub(pub, body_json, sig));               /* sig over body */
    free(body_json);

    free(wire); free(pub); cJSON_Delete(m);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_plain_frame);
    RUN_TEST(test_signed_sealed_roundtrip);
    return UNITY_END();
}
