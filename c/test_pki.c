/*
 * test_pki.c — Unity tests for pki.c
 *
 * Uses the shared ../fixtures/jwks.json key set for cross-language interop.
 * Writes  ../fixtures/sig_c.json  so other languages can verify it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"

/* ── pull in pki.c directly ─────────────────────────────────────────── */
#include "pki.c"

/* ── helpers ────────────────────────────────────────────────────────── */

#define FIXTURES  "../fixtures"
#define JWKS_FILE FIXTURES "/jwks.json"
#define SIG_OUT   FIXTURES "/sig_c.json"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* ── setUp / tearDown ───────────────────────────────────────────────── */

void setUp(void) {
    pki_free();
}

void tearDown(void) {
    pki_free();
}

/* ── tests ──────────────────────────────────────────────────────────── */

void test_init_loads_shared_keys(void) {
    int r = pki_init(JWKS_FILE);
    TEST_ASSERT_EQUAL_INT(0, r);
    TEST_ASSERT_NOT_NULL(signing_priv);
    TEST_ASSERT_NOT_NULL(signing_pub);
    TEST_ASSERT_NOT_NULL(encrypting_priv);
    TEST_ASSERT_NOT_NULL(encrypting_pub);
}

void test_sign_verify_roundtrip(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    char *sig = pki_sign("Hello World");
    TEST_ASSERT_NOT_NULL(sig);
    TEST_ASSERT_EQUAL_INT(1, pki_verify("Hello World", sig));
    free(sig);
}

void test_verify_wrong_message_fails(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    char *sig = pki_sign("Hello World");
    TEST_ASSERT_NOT_NULL(sig);
    TEST_ASSERT_EQUAL_INT(0, pki_verify("Wrong message", sig));
    free(sig);
}

void test_encrypt_decrypt_roundtrip(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    const char *plain = "Secret message";
    char *ct = pki_encrypt(plain);
    TEST_ASSERT_NOT_NULL(ct);
    char *pt = pki_decrypt(ct);
    TEST_ASSERT_NOT_NULL(pt);
    TEST_ASSERT_EQUAL_STRING(plain, pt);
    free(ct);
    free(pt);
}

void test_generate_creates_file(void) {
    const char *tmp = "/tmp/pki_test_gen.json";
    remove(tmp);
    int r = pki_generate(tmp);
    TEST_ASSERT_EQUAL_INT(0, r);
    char *json = read_file(tmp);
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_TRUE(strlen(json) > 10);
    free(json);
    remove(tmp);
}

void test_export_import_roundtrip(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_generate("/tmp/pki_rtrip.json"));
    char *exported = pki_export();
    TEST_ASSERT_NOT_NULL(exported);

    pki_free();
    int r = pki_import(exported);
    free(exported);
    TEST_ASSERT_EQUAL_INT(0, r);

    char *sig = pki_sign("roundtrip test");
    TEST_ASSERT_NOT_NULL(sig);
    TEST_ASSERT_EQUAL_INT(1, pki_verify("roundtrip test", sig));
    free(sig);
    remove("/tmp/pki_rtrip.json");
}

/* write sig_c.json so other languages can verify it */
void test_write_cross_lang_fixture(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    char *sig = pki_sign("Hello World");
    TEST_ASSERT_NOT_NULL(sig);

    /* wrap: {"lang":"c","message":"Hello World","signature":"<sig>"} */
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "lang", "c");
    cJSON_AddStringToObject(rec, "message", "Hello World");
    cJSON_AddStringToObject(rec, "signature", sig);
    char *out = cJSON_PrintUnformatted(rec);
    cJSON_Delete(rec);
    free(sig);

    FILE *f = fopen(SIG_OUT, "w");
    TEST_ASSERT_NOT_NULL(f);
    fputs(out, f);
    fclose(f);
    free(out);
}

/* verify signatures produced by every other language */
static void verify_cross_lang(const char *lang) {
    char path[256];
    snprintf(path, sizeof(path), FIXTURES "/sig_%s.json", lang);
    char *buf = read_file(path);
    if (!buf) {
        TEST_IGNORE_MESSAGE("fixture not found — skipping cross-lang verify");
        return;
    }
    cJSON *rec = cJSON_Parse(buf);
    free(buf);
    if (!rec) { TEST_FAIL_MESSAGE("failed to parse fixture"); return; }

    const char *msg = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(rec, "message"));
    const char *sig = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(rec, "signature"));
    if (!msg || !sig) { cJSON_Delete(rec); TEST_FAIL_MESSAGE("missing fields"); return; }

    int ok = pki_verify(msg, sig);
    cJSON_Delete(rec);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, ok, lang);
}

void test_verify_erlang(void)     { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("erlang"); }
void test_verify_python(void)     { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("python"); }
void test_verify_javascript(void) { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("javascript"); }
void test_verify_ruby(void)       { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("ruby"); }
void test_verify_rust(void)       { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("rust"); }
void test_verify_go(void)         { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("go"); }
void test_verify_java(void)       { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("java"); }
void test_verify_csharp(void)     { TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE)); verify_cross_lang("csharp"); }

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_init_loads_shared_keys);
    RUN_TEST(test_sign_verify_roundtrip);
    RUN_TEST(test_verify_wrong_message_fails);
    RUN_TEST(test_encrypt_decrypt_roundtrip);
    RUN_TEST(test_generate_creates_file);
    RUN_TEST(test_export_import_roundtrip);
    RUN_TEST(test_write_cross_lang_fixture);
    RUN_TEST(test_verify_erlang);
    RUN_TEST(test_verify_python);
    RUN_TEST(test_verify_javascript);
    RUN_TEST(test_verify_ruby);
    RUN_TEST(test_verify_rust);
    RUN_TEST(test_verify_go);
    RUN_TEST(test_verify_java);
    RUN_TEST(test_verify_csharp);

    return UNITY_END();
}
