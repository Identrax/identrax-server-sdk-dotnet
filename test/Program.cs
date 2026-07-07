using System.Text.Json;
using Identrax;

// Cross-language vector pin. Run: dotnet run --project test
var vectors = JsonDocument.Parse(
    File.ReadAllText("../fixtures/crypto_vectors.json")).RootElement;
int failures = 0;
void Check(bool condition, string name)
{
    Console.WriteLine((condition ? "ok   " : "FAIL ") + name);
    if (!condition) failures++;
}

Check(IdentraxCrypto.Sha256Hex("abc"u8.ToArray()) ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");
Check(IdentraxCrypto.NinHash("12345678901") ==
      "254aa248acb47dd654ca3ea53f48c2c26d641d23d7e2e93a1ec56258df7674c4", "nin_hash");

var ed = vectors.GetProperty("ed25519");
Check(IdentraxCrypto.Ed25519Verify(
    ed.GetProperty("public_key_b64url").GetString()!,
    ed.GetProperty("message_utf8").GetString()!,
    ed.GetProperty("signature_b64url").GetString()!), "ed25519 verifies");
Check(!IdentraxCrypto.Ed25519Verify(
    ed.GetProperty("public_key_b64url").GetString()!,
    ed.GetProperty("message_utf8").GetString()! + "x",
    ed.GetProperty("signature_b64url").GetString()!), "tampered ed25519 fails");

var wh = vectors.GetProperty("webhook_hmac");
long ts = wh.GetProperty("timestamp").GetInt64();
Check(IdentraxCrypto.VerifyWebhookSignature(
    wh.GetProperty("secret_utf8").GetString()!, wh.GetProperty("header").GetString()!,
    wh.GetProperty("body_utf8").GetString()!, ts + 10), "webhook verifies");
Check(!IdentraxCrypto.VerifyWebhookSignature(
    wh.GetProperty("secret_utf8").GetString()!, wh.GetProperty("header").GetString()!,
    "{}", ts + 10), "tampered webhook fails");
Check(!IdentraxCrypto.VerifyWebhookSignature(
    wh.GetProperty("secret_utf8").GetString()!, wh.GetProperty("header").GetString()!,
    wh.GetProperty("body_utf8").GetString()!, ts + 3600), "stale webhook fails");

if (failures > 0) { Console.Error.WriteLine($"{failures} failure(s)"); Environment.Exit(1); }
Console.WriteLine("ALL VECTORS OK");
