# Identrax Server SDK — .NET

.NET 8 client for the [Identrax](https://github.com/Identrax) v2 **org API**.

**Package:** `Identrax.Sdk` · **Repository:** [`identrax-server-sdk-dotnet`](https://github.com/Identrax/identrax-server-sdk-dotnet)

## Quick start

```csharp
var client = new IdentraxClient("https://api.identrax.com", "key_...", "sec_...");
var verification = await client.CreateVerificationAsync("12345678901", ["identity.basic"], "account_opening");
```

## Tests

```bash
dotnet build src/Identrax.csproj && dotnet run --project test
```

## License

Proprietary — © Identrax.
