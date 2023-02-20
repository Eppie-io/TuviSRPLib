# TuviSRPLib
TuviSRPLib is a C# port of a custom implementation of SRP protocol used by ProtonMail. The port is based on [BounceCastle implementation of SRP-6](https://github.com/bcgit/bc-csharp/tree/master/crypto/src/crypto/agreement/srp) with appropriate changes. This library also provides classes to emulate server and client side behavior for testing.

TuviSRPLib contains the following main classes:
- ProtonSRPServer — server side emulation;
- ProtonSRPClient — imitates client side emulation;
- ProtonSRPUtilities — main calculations;
- ExtendedHashDigest — an implementation of hash algorithm used by Proton.

To use this library and imitate interaction between server and client follow next example:

```
    BigInteger N = new BigInteger(1, byteArray); // group order - any big prime number you want to use
    BigInteger g = new BigInteger("2"); // group generator - always equals 2 in Proton realization
    
    string password = "qwerty"; // any password
    string salt = "some bytes"; // exactly 10 symbols for Proton realization. Bcrypt uses salt with specific length.

    Encoding enc = Encoding.UTF8;
    byte[] passwordBytes = enc.GetBytes(password);
    byte[] saltBytes = enc.GetBytes(salt);

    // Sides creation
    ProtonSRPClient client = new ProtonSRPClient();
    ProtonSRPServer server = new ProtonSRPServer();
    IDigest digest = new ExtendedHashDigest();

    // Verifier creation
    var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, passwordBytes);

    // Sides initialization
    server.Init(N, g, verifier, digest, new SecureRandom());
    client.Init(N, g, digest, new SecureRandom());

    // Credential genration for both sides
    BigInteger pubA = client.GenerateClientCredentials(saltBytes, passwordBytes);
    BigInteger pubB = server.GenerateServerCredentials();

    server.CalculateSecret(pubA);
    client.CalculateSecret(pubB);

    BigInteger M1 = client.CalculateClientEvidenceMessage(); // M1 message creation
    
    if (server.VerifyClientEvidenceMessage(M1)) // M1 message verifying
    {
        BigInteger M2 = server.CalculateServerEvidenceMessage(); // M2 message creation

        if (client.VerifyServerEvidenceMessage(M2)) // M2 message verifying
        {
            BigInteger clientKey = client.CalculateSessionKey();
            BigInteger serverKey = server.CalculateSessionKey();
        }
    }
```
