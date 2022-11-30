using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
using TuviSRPLib;
using TuviSRPLib.Utils;

namespace TuviSRPLibTests
{
    internal class ProtonSRPTests
    {
        [Test]
        public void FullCycleOfWorkTest()
        {
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            BigInteger g = new BigInteger("2");
            
            string password = "qwerty";
            string salt = "some bytes"; // exactly 10 symbols for Proton protocol. Bcrypt uses salt with specific length.

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = enc.GetBytes(salt);

            ProtonSRPClient client = new ProtonSRPClient();
            ProtonSRPServer server = new ProtonSRPServer();
            IDigest digest = new ExtendedHashDigest();

            var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, passwordBytes);

            server.Init(N, g, verifier, digest, new SecureRandom());
            client.Init(N, g, digest, new SecureRandom());

            BigInteger pubA = client.GenerateClientCredentials(saltBytes, passwordBytes);
            BigInteger pubB = server.GenerateServerCredentials();

            server.CalculateSecret(pubA);
            client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.IsTrue(server.VerifyClientEvidenceMessage(M1), "Message M1 is not verified.");

            BigInteger M2 = server.CalculateServerEvidenceMessage();

            Assert.IsTrue(client.VerifyServerEvidenceMessage(M2), "Message M2 is not verified.");

            BigInteger clientKey = client.CalculateSessionKey();
            BigInteger serverKey = server.CalculateSessionKey();

            Assert.AreEqual(clientKey, serverKey);
        }

        [Test]
        public void ClientSideWorkWithSpecificRandomTest()
        {
            //pubB
            string testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
            var decodedPubB = Base64.Decode(testServerEphemeral);
            BigInteger pubB = new BigInteger(1, decodedPubB.Reverse().ToArray());

            //M2
            string testServerProof = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g==";
            var decodedExpectedM2 = Base64.Decode(testServerProof);
            BigInteger expectedM2 = new BigInteger(1, decodedExpectedM2.Reverse().ToArray());

            //M1
            string testClientProof = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==";
            var decodedExpectedM1 = Base64.Decode(testClientProof);
            BigInteger expectedM1 = new BigInteger(1, decodedExpectedM1.Reverse().ToArray());

            //N and g
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            BigInteger g = new BigInteger("2");

            //Digest
            IDigest digest = new ExtendedHashDigest();

            //Test data
            //string identity = "jakubqa"; Proton SRP protocol doesn't use UserName(Identity) calculating Verifier
            string password = "abc123";
            string salt = "yKlc5/CvObfoiw==";

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = Base64.Decode(salt);

            //Client creation
            ProtonSRPClient client = new ProtonSRPClient();
            client.Init(N, g, digest, new MyUnsecureRandom());
            client.GenerateClientCredentials(saltBytes,passwordBytes);

            client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.AreEqual(expectedM1, M1);

            Assert.IsTrue(client.VerifyServerEvidenceMessage(expectedM2), "Message M2 is not verified.");
        }

        [Test]
        public void ClientSideWorkWithStringsAndSpecificRandomTest()
        {
            //pubB
            string testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
            
            //M2
            string testServerProof = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g==";
            
            //M1
            string testClientProof = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==";
            
            //N and g
            var N = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            BigInteger g = new BigInteger("2");

            //Digest
            IDigest digest = new ExtendedHashDigest();

            //Test data
            //string identity = "jakubqa"; Proton SRP protocol doesn't use UserName(Identity) calculating Verifier
            string password = "abc123";
            string salt = "yKlc5/CvObfoiw==";

            //Client creation
            ProtonSRPClient client = new ProtonSRPClient();
            client.Init(N, g, digest, new MyUnsecureRandom());
            client.GenerateClientCredentials(salt, password);

            client.CalculateSecret(testServerEphemeral);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.AreEqual(testClientProof, M1.ToBase64());

            Assert.IsTrue(client.VerifyServerEvidenceMessage(testServerProof), "Message M2 is not verified.");
        }

        [TestCase("123456")]
        [TestCase("qwerty123")]
        public void WrongPassword_FalseVerifyingTests(string wrongPassword)
        {
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            BigInteger g = new BigInteger("2");

            string password = "qwerty"; // expected password
            string salt = "some bytes"; // expected salt

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = enc.GetBytes(salt);
            byte[] wrongPasswordBytes = enc.GetBytes(wrongPassword);

            ProtonSRPClient client = new ProtonSRPClient();
            ProtonSRPServer server = new ProtonSRPServer();
            IDigest digest = new ExtendedHashDigest();

            var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, passwordBytes);

            server.Init(N, g, verifier, digest, new SecureRandom());
            client.Init(N, g, digest, new SecureRandom());

            BigInteger pubA = client.GenerateClientCredentials(saltBytes, wrongPasswordBytes);
            BigInteger pubB = server.GenerateServerCredentials();

            server.CalculateSecret(pubA);
            client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.IsFalse(server.VerifyClientEvidenceMessage(M1), "Message M1 is verified while it should not.");
        }

        [TestCase("1234567890")]
        [TestCase("qwerty1234")]
        [TestCase("OtherBytes")]
        public void WrongSalt_FalseVerifyingTests(string wrongSalt)
        {
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            BigInteger g = new BigInteger("2");

            string password = "qwerty"; // expected password
            string salt = "some bytes"; // expected salt

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = enc.GetBytes(salt);
            byte[] wrongSaltBytes = enc.GetBytes(wrongSalt);

            ProtonSRPClient client = new ProtonSRPClient();
            ProtonSRPServer server = new ProtonSRPServer();
            IDigest digest = new ExtendedHashDigest();

            var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, passwordBytes);

            server.Init(N, g, verifier, digest, new SecureRandom());
            client.Init(N, g, digest, new SecureRandom());

            BigInteger pubA = client.GenerateClientCredentials(wrongSaltBytes, passwordBytes);
            BigInteger pubB = server.GenerateServerCredentials();

            server.CalculateSecret(pubA);
            client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.IsFalse(server.VerifyClientEvidenceMessage(M1), "Message M1 is verified while it should not.");
        }

        [TestCase("SaltBytes")]
        [TestCase("A lot Bytes")]
        public void WrongSaltSize_ThrowArgumentExceptionTests(string wrongSalt)
        {
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            BigInteger g = new BigInteger("2");

            string password = "qwerty"; 

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] wrongSaltBytes = enc.GetBytes(wrongSalt);

            IDigest digest = new ExtendedHashDigest();

            ProtonSRPClient client = new ProtonSRPClient();
            client.Init(N, g, digest, new SecureRandom());

            Assert.Throws<ArgumentException>(() => client.GenerateClientCredentials(wrongSaltBytes, passwordBytes));
        }
    }
}
