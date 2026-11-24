// mesgd-sdk C# Ping/Pong Sample
// ================================
// Demonstrates the full mesgd-sdk lifecycle in C# (.NET 8):
//   1. Initialise local PKI keys (System.Security.Cryptography)
//   2. Register our public keys with the mesgd echo server
//   3. Open a TLS WebSocket connection (System.Net.WebSockets)
//   4. Send 3 signed+encrypted "ping" messages
//   5. Receive and verify the echoed "pong" response each time
//
// Build:  dotnet build
// Run:    dotnet run

using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

// ---------------------------------------------------------------------------
// Configuration (override via environment variables)
// ---------------------------------------------------------------------------
string mesgdUrl    = Environment.GetEnvironmentVariable("MESGD_URL")     ?? "wss://echo.mesgd.org/ws";
string pubJwkPath  = Environment.GetEnvironmentVariable("MESGD_PUB_JWK") ?? "mesgd_pub.json";
int    rounds      = int.Parse(Environment.GetEnvironmentVariable("MESGD_ROUNDS") ?? "3");

Console.WriteLine("=== mesgd-sdk C# Ping/Pong Sample ===\n");

// ------------------------------------------------------------------
// Step 1: Initialise PKI
//   Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 key
//   pairs and saves them.  Note: C# produces IEEE P1363 ECDSA
//   signatures internally; PKI.Sign() converts to DER for
//   cross-language interoperability (see plan.md).
// ------------------------------------------------------------------
Console.WriteLine("Step 1: Initialising PKI …");
PKI.Init();
Console.WriteLine("        Keys ready.\n");

// ------------------------------------------------------------------
// Step 2: Load mesgd's public encryption key
// ------------------------------------------------------------------
Console.WriteLine($"Step 2: Loading mesgd public key from '{pubJwkPath}' …");
Dictionary<string, object> mesgdPubJwk = LoadMesgdPubJwk(pubJwkPath);
Console.WriteLine("        Loaded.\n");

// ------------------------------------------------------------------
// Step 3: Register with mesgd
// ------------------------------------------------------------------
Console.WriteLine("Step 3: Registering with mesgd …");
string registrationCt = PKI.Register(JsonSerializer.Serialize(mesgdPubJwk));
Console.WriteLine($"        Registration payload (first 40 chars): {registrationCt[..Math.Min(40, registrationCt.Length)]}…\n");

// ------------------------------------------------------------------
// Step 4: Connect WebSocket
// ------------------------------------------------------------------
Console.WriteLine($"Step 4: Connecting to {mesgdUrl} …");
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
using var wsClient = new ClientWebSocket();
await wsClient.ConnectAsync(new Uri(mesgdUrl), cts.Token);

// Send the registration ciphertext as the opening handshake frame
byte[] regBytes = Encoding.UTF8.GetBytes(registrationCt);
await wsClient.SendAsync(regBytes, WebSocketMessageType.Text, true, cts.Token);
Console.WriteLine("        Connected.\n");

// ------------------------------------------------------------------
// Step 5: Ping / pong loop
// ------------------------------------------------------------------
Console.WriteLine($"Step 5: Starting {rounds}-round ping/pong …\n");
var receiveBuffer = new byte[65536];

try
{
    for (int i = 1; i <= rounds; i++)
    {
        string message = $"Hello from mesgd-sdk! C# ping #{i}";

        // Sign + encrypt the message
        string signature  = PKI.Sign(message);
        string envelope   = JsonSerializer.Serialize(new { payload = message, signature });
        string ciphertext = PKI.EncryptWith(JsonSerializer.Serialize(mesgdPubJwk), envelope);

        Console.WriteLine($"  [{i}/{rounds}] Sending  : {message}");
        byte[] sendBytes = Encoding.UTF8.GetBytes(ciphertext);
        await wsClient.SendAsync(sendBytes, WebSocketMessageType.Text, true, cts.Token);

        // Receive, decrypt, and verify
        var result   = await wsClient.ReceiveAsync(receiveBuffer, cts.Token);
        string raw   = Encoding.UTF8.GetString(receiveBuffer, 0, result.Count);
        string plain = PKI.Decrypt(raw);

        // Parse the envelope
        using var doc   = JsonDocument.Parse(plain);
        string payload  = doc.RootElement.GetProperty("payload").GetString()!;
        string sig      = doc.RootElement.GetProperty("signature").GetString()!;

        // Verify using mesgd's signing public key
        if (!PKI.CheckWithPub(JsonSerializer.Serialize(mesgdPubJwk), payload, sig))
            throw new InvalidOperationException("Signature verification failed on received message");

        Console.WriteLine($"  [{i}/{rounds}] Received : {payload}");

        if (payload != message)
            throw new InvalidOperationException($"Echo mismatch — expected: {message}, got: {payload}");

        Console.WriteLine($"  [{i}/{rounds}] \u2713 Echo verified\n");
    }
}
finally
{
    if (wsClient.State == WebSocketState.Open)
        await wsClient.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
    Console.WriteLine("Connection closed.");
}

Console.WriteLine($"\nAll {rounds} ping/pong rounds passed.");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static Dictionary<string, object> LoadMesgdPubJwk(string path)
{
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"ERROR: mesgd public key file not found: {path}");
        Console.Error.WriteLine("  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json");
        Environment.Exit(1);
    }
    string json = File.ReadAllText(path);
    return JsonSerializer.Deserialize<Dictionary<string, object>>(json)
        ?? throw new InvalidOperationException($"Failed to parse {path}");
}
