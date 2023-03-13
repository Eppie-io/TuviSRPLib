using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace TuviSRPLib
{
    /// <summary>
    /// Implements the client side of SRP protocol used in Proton realization with all changes. Based on the BouncyCastle lib
    /// https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/agreement/srp/SRP6Client.cs
    /// Proton SRP protocol doesn't use UserName(Identity) calculating Verifier.
    /// </summary>
    public partial class ProtonSRPClient
    {
        protected BigInteger N;
        protected BigInteger g; // In Proton g = 2 always

        protected BigInteger privA;
        protected BigInteger pubA;

        protected BigInteger B;

        protected BigInteger x;
        protected BigInteger u;
        protected BigInteger S;

        protected BigInteger M1;
        protected BigInteger M2;
        protected BigInteger Key;

        protected IDigest digest;
        protected SecureRandom random;

        public ProtonSRPClient()
        {
        }

        /**
	     * Initialises the client to begin new authentication attempt
	     * @param N The safe prime associated with the client's verifier
	     * @param g The group parameter associated with the client's verifier
	     * @param digest The digest algorithm associated with the client's verifier
	     * @param random For key generation
	     */
        public virtual void Init(BigInteger N, BigInteger g, IDigest digest, SecureRandom random)
        {
            // According to ProtonMail documentation N size should be 2048 bits.
            int bitSize = 2048;
            int bitInByte = sizeof(byte) * 8;
            int count = bitSize / bitInByte;

            byte[] bytes = Enumerable.Repeat(byte.MaxValue, count).ToArray();
            bytes[0] = 0x7f;

            BigInteger border = new BigInteger(1, bytes);

            // It is necessary but not sufficient verification of N size (2048 bits).
            // You should be sure that you received N from the server and it has not been changed.
            string dif = N.Subtract(border).ToString();
            if (dif[0] == '-')
            {
                throw new ArgumentOutOfRangeException(nameof(N), "N should be a 2048-bit number.");
            }

            this.N = N;
            this.g = g;
            this.digest = digest;
            this.random = random;
        }

        public virtual void Init(Srp6GroupParameters group, IDigest digest, SecureRandom random)
        {
            Init(group.N, group.G, digest, random);
        }

        public virtual void Init(string base64N, BigInteger g, IDigest digest, SecureRandom random)
        {
            if (string.IsNullOrEmpty(base64N))
            {
                throw new ArgumentException("Parameter can not be null or empty", nameof(base64N));
            }

            var decodedBase64N = Base64.Decode(base64N);
            BigInteger N = new BigInteger(1, decodedBase64N.Reverse().ToArray());
            Init(N, g, digest, random);
        }

        public virtual void SimpleInit(string base64N)
        {
            if (string.IsNullOrEmpty(base64N))
            {
                throw new ArgumentException("Parameter can not be null or empty", nameof(base64N));
            }

            var decodedBase64N = Base64.Decode(base64N);
            BigInteger N = new BigInteger(1, decodedBase64N.Reverse().ToArray());
            BigInteger g = new BigInteger("2");
            Init(N, g, new ExtendedHashDigest(), new SecureRandom());
        }

        /**
	     * Generates client's credentials given the client's salt and password. 
	     * Proton SRP protocol doesn't use UserName(Identity) calculating Verifier.
	     * @param salt The salt used in the client's verifier.
	     * @param password The user's password
	     * @return Client's public value to send to server
	     */
        public virtual BigInteger GenerateClientCredentials(byte[] salt, byte[] password)
        {
            if (salt is null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.x = ProtonSRPUtilities.CalculateX(digest, N, salt, password);
            this.privA = SelectPrivateValue();
            this.pubA = g.ModPow(privA, N);

            return pubA;
        }

        public virtual BigInteger GenerateClientCredentials(string base64Salt, string password)
        {
            if (string.IsNullOrEmpty(base64Salt))
            {
                throw new ArgumentException("Salt can not be null or empty", nameof(base64Salt));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password can not be null or empty", nameof(password));
            }

            byte[] saltBytes = Base64.Decode(base64Salt);
            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(password);

            this.x = ProtonSRPUtilities.CalculateX(digest, N, saltBytes, passwordBytes);
            this.privA = SelectPrivateValue();
            this.pubA = g.ModPow(privA, N);

            return pubA;
        }

        /**
	     * Generates client's verification message given the server's credentials
	     * @param serverB The server's credentials
	     * @return Client's verification message for the server
	     * @throws CryptoException If server's credentials are invalid
	     */
        public virtual BigInteger CalculateSecret(BigInteger serverB)
        {
            this.B = ProtonSRPUtilities.ValidatePublicValue(N, serverB);
            this.u = ProtonSRPUtilities.CalculateU(digest, N, pubA, B);
            this.S = CalculateS();

            return S;
        }

        public virtual BigInteger CalculateSecret(string serverB)
        {
            if (string.IsNullOrEmpty(serverB))
            {
                throw new ArgumentException("Server public key can not be null or empty", nameof(serverB));
            }

            var decodedPubB = Base64.Decode(serverB);
            BigInteger pubB = new BigInteger(1, decodedPubB.Reverse().ToArray());

            return CalculateSecret(pubB);
        }

        protected virtual BigInteger SelectPrivateValue()
        {
            return ProtonSRPUtilities.GeneratePrivateValue(digest, N, g, random);
        }

        private BigInteger CalculateS()
        {
            BigInteger k = ProtonSRPUtilities.CalculateK(digest, g, N);

            var modMinusOne = N.Subtract(new BigInteger("1"));

            BigInteger tempExp = u.Multiply(x).Mod(modMinusOne);

            BigInteger exp = tempExp.Add(privA).Mod(modMinusOne);
            BigInteger tmp = g.ModPow(x, N).Multiply(k).Mod(N);
            var basement = B.Subtract(tmp).Mod(N);

            var result = basement.ModPow(exp, N);

            return result;
        }

        /**
	     * Computes the client evidence message M1 using the previously received values.
	     * To be called after calculating the secret S.
	     * @return M1: the client side generated evidence message
	     * @throws CryptoException
	     */
        public virtual BigInteger CalculateClientEvidenceMessage()
        {
            // Verify pre-requirements
            if (this.pubA == null || this.B == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute M1: " +
                        "some data are missing from the previous operations (A,B,S)");
            }
            // compute the client evidence message 'M1'
            this.M1 = ProtonSRPUtilities.CalculateM1(digest, N, pubA, B, S);
            return M1;
        }

        /** Authenticates the server evidence message M2 received and saves it only if correct.
	     * @param M2: the server side generated evidence message
	     * @return A boolean indicating if the server message M2 was the expected one.
	     * @throws CryptoException
	     */
        public virtual bool VerifyServerEvidenceMessage(BigInteger serverM2)
        {
            // Verify pre-requirements
            if (this.pubA == null || this.M1 == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute and verify M2: " +
                        "some data are missing from the previous operations (A,M1,S)");
            }

            // Compute the own server evidence message 'M2'
            BigInteger computedM2 = ProtonSRPUtilities.CalculateM2(digest, N, pubA, M1, S);
            if (computedM2.Equals(serverM2))
            {
                this.M2 = serverM2;
                return true;
            }
            return false;
        }

        public virtual bool VerifyServerEvidenceMessage(string serverM2)
        {
            if (string.IsNullOrEmpty(serverM2))
            {
                throw new ArgumentException("Server verification message can not be null or empty", nameof(serverM2));
            }

            var decodedExpectedM2 = Base64.Decode(serverM2);
            BigInteger M2 = new BigInteger(1, decodedExpectedM2.Reverse().ToArray());

            return VerifyServerEvidenceMessage(M2);
        }

        /**
	     * Computes the final session key as a result of the SRP successful mutual authentication
	     * To be called after verifying the server evidence message M2.
	     * @return Key: the mutually authenticated symmetric session key
	     * @throws CryptoException
	     */
        public virtual BigInteger CalculateSessionKey()
        {
            // Verify pre-requirements (here we enforce a previous calculation of M1 and M2)
            if (this.S == null || this.M1 == null || this.M2 == null)
            {
                throw new CryptoException("Impossible to compute Key: " +
                        "some data are missing from the previous operations (S,M1,M2)");
            }
            this.Key = ProtonSRPUtilities.CalculateKey(digest, N, S);
            return Key;
        }
    }
}
