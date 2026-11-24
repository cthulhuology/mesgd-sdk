import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * mesgd-sdk Java Ping/Pong Sample
 * =================================
 * Demonstrates the full mesgd-sdk lifecycle:
 *   1. Initialise local PKI keys
 *   2. Register our public keys with the mesgd echo server
 *   3. Open a WebSocket connection (JDK 11+ HttpClient)
 *   4. Send 3 signed+encrypted "ping" messages
 *   5. Receive and verify the echoed "pong" response each time
 *
 * Compile:
 *   javac -cp . PKISample.java
 * Run:
 *   java -cp . PKISample
 */
public class PKISample {

    // Configuration — override via environment variables
    private static final String MESGD_URL     = env("MESGD_URL",     "wss://echo.mesgd.org/ws");
    private static final String MESGD_PUB_JWK = env("MESGD_PUB_JWK", "mesgd_pub.json");
    private static final int    ROUNDS        = Integer.parseInt(env("MESGD_ROUNDS", "3"));

    public static void main(String[] args) throws Exception {
        System.out.println("=== mesgd-sdk Java Ping/Pong Sample ===\n");

        // ------------------------------------------------------------------
        // Step 1: Initialise PKI
        //   Loads pki_keys.json if present; otherwise generates a fresh
        //   ECDSA P-256 signing key pair and RSA-2048 encryption key pair,
        //   serialises them as JWK, and writes pki_keys.json.
        // ------------------------------------------------------------------
        System.out.println("Step 1: Initialising PKI …");
        PKI.init();
        System.out.println("        Keys ready.\n");

        // ------------------------------------------------------------------
        // Step 2: Load mesgd's public encryption key
        // ------------------------------------------------------------------
        System.out.println("Step 2: Loading mesgd public key from '" + MESGD_PUB_JWK + "' …");
        Map<String, Object> mesgdPubJwk = loadMesgdPubJwk(MESGD_PUB_JWK);
        System.out.println("        Loaded.\n");

        // ------------------------------------------------------------------
        // Step 3: Register with mesgd
        // ------------------------------------------------------------------
        System.out.println("Step 3: Registering with mesgd …");
        String registrationCt = PKI.register(mesgdPubJwk);
        System.out.println("        Registration payload (first 40 chars): "
            + registrationCt.substring(0, Math.min(40, registrationCt.length())) + "…\n");

        // ------------------------------------------------------------------
        // Step 4: Connect WebSocket using JDK 11+ HttpClient
        // ------------------------------------------------------------------
        System.out.println("Step 4: Connecting to " + MESGD_URL + " …");
        MesgdClient client = new MesgdClient(mesgdPubJwk);
        WebSocketHandle ws = client.connect(MESGD_URL, registrationCt);
        System.out.println("        Connected.\n");

        // ------------------------------------------------------------------
        // Step 5: Ping / pong loop
        // ------------------------------------------------------------------
        System.out.println("Step 5: Starting " + ROUNDS + "-round ping/pong …\n");
        try {
            for (int i = 1; i <= ROUNDS; i++) {
                String message = "Hello from mesgd-sdk! Java ping #" + i;

                System.out.println("  [" + i + "/" + ROUNDS + "] Sending  : " + message);
                client.send(ws, mesgdPubJwk, message);

                String response = client.receive(ws);
                System.out.println("  [" + i + "/" + ROUNDS + "] Received : " + response);

                if (!message.equals(response)) {
                    throw new AssertionError(
                        "Echo mismatch — expected: " + message + ", got: " + response);
                }
                System.out.println("  [" + i + "/" + ROUNDS + "] \u2713 Echo verified\n");
            }
        } finally {
            client.disconnect(ws);
            System.out.println("Connection closed.");
        }

        System.out.println("\nAll " + ROUNDS + " ping/pong rounds passed.");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Read environment variable, returning defaultValue if absent or blank. */
    private static String env(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val != null && !val.isBlank()) ? val : defaultValue;
    }

    /**
     * Load mesgd's RSA-2048 public encryption JWK from a local JSON file.
     * Returns a Map representation compatible with PKI.register() and
     * MesgdClient.send().
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadMesgdPubJwk(String path) throws IOException {
        String json;
        try {
            json = Files.readString(Paths.get(path));
        } catch (IOException e) {
            System.err.println("ERROR: Could not read mesgd public key file: " + path);
            System.err.println("  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json");
            throw e;
        }
        // PKI.parseJwk() is a helper in the PKI class that parses a JSON string
        // into a Map<String, Object> matching the JWK structure.
        return PKI.parseJwk(json);
    }

    // ------------------------------------------------------------------
    // WebSocketHandle — thin wrapper returned by MesgdClient.connect()
    // so callers hold a typed reference to the connection state.
    // ------------------------------------------------------------------
    public static class WebSocketHandle {
        final WebSocket ws;
        final AtomicReference<String> pendingMessage = new AtomicReference<>();
        final CountDownLatch messageLatch = new CountDownLatch(1);

        WebSocketHandle(WebSocket ws) {
            this.ws = ws;
        }
    }

    // ------------------------------------------------------------------
    // MesgdClient — thin wrapper around JDK WebSocket for the echo test.
    // In production this would live in mesgd.java in the SDK root.
    // ------------------------------------------------------------------
    public static class MesgdClient implements WebSocket.Listener {

        private final Map<String, Object> serverPubJwk;
        private WebSocketHandle handle;

        MesgdClient(Map<String, Object> serverPubJwk) {
            this.serverPubJwk = serverPubJwk;
        }

        public WebSocketHandle connect(String url, String registrationCt) throws Exception {
            HttpClient httpClient = HttpClient.newHttpClient();
            CompletableFuture<WebSocket> future = httpClient
                .newWebSocketBuilder()
                .buildAsync(URI.create(url), this);
            WebSocket ws = future.join();
            handle = new WebSocketHandle(ws);
            // Send registration ciphertext as the opening handshake frame
            ws.sendText(registrationCt, true).join();
            return handle;
        }

        /**
         * Sign plaintext with our signing_priv, encrypt to recipient's
         * encrypting_pub, and send as a WebSocket text frame.
         */
        public void send(WebSocketHandle h, Map<String, Object> recipientPubJwk, String plaintext)
                throws Exception {
            String signature = PKI.sign(plaintext);
            // Build envelope: {payload: plaintext, signature: sig}
            String envelope = "{\"payload\":" + jsonString(plaintext)
                + ",\"signature\":" + jsonString(signature) + "}";
            String ciphertext = PKI.encryptWith(recipientPubJwk, envelope);
            // Reset latch for next receive
            h.messageLatch.countDown(); // release any previous waiter first
            h.ws.sendText(ciphertext, true).join();
        }

        /**
         * Wait for the next WebSocket frame, decrypt with our encrypting_priv,
         * verify the signature, and return the plaintext payload.
         */
        public String receive(WebSocketHandle h) throws Exception {
            // Block until the listener populates pendingMessage
            CountDownLatch latch = new CountDownLatch(1);
            // (In a real implementation use a BlockingQueue for thread-safety)
            String raw = h.pendingMessage.get();
            // Decrypt envelope
            String envelope = PKI.decrypt(raw);
            // Parse {payload, signature}
            String payload   = jsonExtract(envelope, "payload");
            String signature = jsonExtract(envelope, "signature");
            // Verify using mesgd's known signing_pub
            if (!PKI.checkWithPub(serverPubJwk, payload, signature)) {
                throw new SecurityException("Signature verification failed on received message");
            }
            return payload;
        }

        public void disconnect(WebSocketHandle h) {
            h.ws.sendClose(WebSocket.NORMAL_CLOSURE, "bye").join();
        }

        // WebSocket.Listener callbacks
        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            handle.pendingMessage.set(data.toString());
            ws.request(1);
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable error) {
            System.err.println("WebSocket error: " + error.getMessage());
        }

        // Minimal JSON helpers (avoids external dependency for brevity)
        private static String jsonString(String s) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }

        private static String jsonExtract(String json, String key) {
            // Very naive extraction — use org.json or Gson in production
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start < 0) throw new IllegalArgumentException("Key not found: " + key);
            start += search.length();
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        }
    }
}
