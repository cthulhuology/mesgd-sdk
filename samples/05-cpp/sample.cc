/**
 * mesgd-sdk C++ Ping/Pong Sample
 * ================================
 * Demonstrates the full mesgd-sdk lifecycle in modern C++ (C++17):
 *   1. Initialise local PKI keys (OpenSSL EVP via pki.hh)
 *   2. Register our public keys with the mesgd echo server
 *   3. Open a TLS WebSocket connection (Boost.Beast)
 *   4. Send 3 signed+encrypted "ping" messages
 *   5. Receive and verify the echoed "pong" response each time
 *
 * Build:  make
 * Run:    ./sample
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>

/* SDK headers — relative to the SDK root */
#include "../../pki.hh"    /* pki::init, pki::sign, pki::encrypt_with, pki::reg, ... */
#include "../../mesgd.hh"  /* mesgd::Client */

namespace asio      = boost::asio;
namespace beast     = boost::beast;
namespace websocket = beast::websocket;
namespace ssl       = asio::ssl;
using     tcp       = asio::ip::tcp;
using     json      = nlohmann::json;

static const int    ROUNDS             = 3;
static const char*  DEFAULT_MESGD_URL  = "wss://echo.mesgd.org/ws";
static const char*  DEFAULT_PUB_JWK    = "mesgd_pub.json";


/** Read the contents of a file into a string. */
static std::string read_file(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    return { std::istreambuf_iterator<char>(ifs),
             std::istreambuf_iterator<char>() };
}

/** Get an environment variable, returning default_val if absent. */
static std::string env(const char* name, const char* default_val) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(default_val);
}


int main() {
    std::cout << "=== mesgd-sdk C++ Ping/Pong Sample ===\n\n";

    const std::string mesgd_url    = env("MESGD_URL",     DEFAULT_MESGD_URL);
    const std::string pub_jwk_path = env("MESGD_PUB_JWK", DEFAULT_PUB_JWK);

    try {
        /* ------------------------------------------------------------------
         * Step 1: Initialise PKI
         * ------------------------------------------------------------------ */
        std::cout << "Step 1: Initialising PKI …\n";
        pki::init();
        std::cout << "        Keys ready.\n\n";

        /* ------------------------------------------------------------------
         * Step 2: Load mesgd's public encryption key
         * ------------------------------------------------------------------ */
        std::cout << "Step 2: Loading mesgd public key from '" << pub_jwk_path << "' …\n";
        json mesgd_pub_jwk = json::parse(read_file(pub_jwk_path));
        std::cout << "        Loaded.\n\n";

        /* ------------------------------------------------------------------
         * Step 3: Register with mesgd
         * ------------------------------------------------------------------ */
        std::cout << "Step 3: Registering with mesgd …\n";
        std::string registration_ct = pki::reg(mesgd_pub_jwk);
        std::cout << "        Registration payload (first 40 chars): "
                  << registration_ct.substr(0, 40) << "…\n\n";

        /* ------------------------------------------------------------------
         * Step 4: Connect WebSocket (Boost.Beast + ASIO)
         * ------------------------------------------------------------------ */
        std::cout << "Step 4: Connecting to " << mesgd_url << " …\n";
        asio::io_context ioc;
        ssl::context ssl_ctx{ssl::context::tlsv12_client};
        ssl_ctx.set_default_verify_paths();

        mesgd::Client client(ioc, ssl_ctx, mesgd_pub_jwk);
        auto ws = client.connect(mesgd_url, registration_ct);
        std::cout << "        Connected.\n\n";

        /* ------------------------------------------------------------------
         * Step 5: Ping / pong loop
         * ------------------------------------------------------------------ */
        std::cout << "Step 5: Starting " << ROUNDS << "-round ping/pong …\n\n";
        for (int i = 1; i <= ROUNDS; ++i) {
            std::string message = "Hello from mesgd-sdk! C++ ping #" + std::to_string(i);

            std::cout << "  [" << i << "/" << ROUNDS << "] Sending  : " << message << "\n";
            client.send(ws, mesgd_pub_jwk, message);

            std::string response = client.receive(ws);
            std::cout << "  [" << i << "/" << ROUNDS << "] Received : " << response << "\n";

            if (response != message) {
                throw std::runtime_error("Echo mismatch — expected: " + message
                    + ", got: " + response);
            }
            std::cout << "  [" << i << "/" << ROUNDS << "] \u2713 Echo verified\n\n";
        }

        client.disconnect(ws);
        std::cout << "Connection closed.\n";

    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }

    std::cout << "\nAll " << ROUNDS << " ping/pong rounds passed.\n";
    return 0;
}
