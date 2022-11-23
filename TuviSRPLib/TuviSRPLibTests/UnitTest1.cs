using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;
using TuviSRPLib;

namespace TuviSRPLibTests
{
    public class Tests
    {
        //[SetUp]
        //public void Setup()
        //{
        //}

        [Test]
        public void Test1()
        {
            var group = Srp6StandardGroups.rfc5054_1024;

            string identity = "ivanov";
            string password = "qwerty";
            string salt = "some salt";

            Encoding enc = Encoding.UTF8;
            byte[] identityBytes = enc.GetBytes(identity);
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = enc.GetBytes(salt);
            
            var verifier = CalculateVerifier(identity, password, salt, group);

            Srp6Client client = new Srp6Client();
            Srp6Server server = new Srp6Server();
            //ProtonDigest digest = new ProtonDigest();
            Sha512Digest digest = new Sha512Digest();
            //Sha1Digest digest = new Sha1Digest();

            server.Init(group, verifier, digest, new SecureRandom());
            client.Init(group, digest, new SecureRandom());

            BigInteger pubA = client.GenerateClientCredentials(saltBytes, identityBytes, passwordBytes);
            BigInteger pubB = server.GenerateServerCredentials();

            BigInteger serverSecret = server.CalculateSecret(pubA);
            BigInteger clientSecret = client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            server.VerifyClientEvidenceMessage(M1);
            Assert.IsTrue(server.VerifyClientEvidenceMessage(M1), "Message M1 is not verified.");
                        
            BigInteger M2 = server.CalculateServerEvidenceMessage();

            Assert.IsTrue(client.VerifyServerEvidenceMessage(M2), "Message M2 is not verified.");
            
            BigInteger clientKey = client.CalculateSessionKey();
            BigInteger serverKey = server.CalculateSessionKey();

            Assert.AreEqual(clientKey, serverKey);
        }

        private BigInteger CalculateVerifier(string identity, string password, string salt, Srp6GroupParameters group)
        {
            Encoding enc = Encoding.UTF8;
            string idPass = identity + ":" + password;
            byte[] idPassBytes = enc.GetBytes(idPass);
            byte[] saltBytes = enc.GetBytes(salt);
            byte[] idPassHash = SHA512.HashData(idPassBytes);

            byte[] saltConcat = saltBytes.Concat(idPassHash).ToArray();
            BigInteger x = new BigInteger(SHA512.HashData(saltConcat));
            return group.G.ModPow(x, group.N);
        }
    }
}