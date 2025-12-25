using System;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace TuviSRPLib
{
    /// <summary>
    /// Implements the server side of SRP protocol used in Proton realization with all changes. Based on the BouncyCastle lib
    /// https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/agreement/srp/SRP6Server.cs
    /// </summary>
    public class ProtonSRPServer
    {
        protected BigInteger N { get; set; }
        protected BigInteger g { get; set; }
        protected BigInteger v { get; set; }

        protected SecureRandom random { get; set; }
        protected IDigest digest { get; set; }

        protected BigInteger A { get; set; }

        protected BigInteger privB { get; set; }
        protected BigInteger pubB { get; set; }

        protected BigInteger u { get; set; }
        protected BigInteger S { get; set; }
        protected BigInteger M1 { get; set; }
        protected BigInteger M2 { get; set; }
        protected BigInteger Key { get; set; }

        public ProtonSRPServer()
        {
        }

        /**
         * Initialises the server to accept a new client authentication attempt
         * @param N The safe prime associated with the client's verifier
         * @param g The group parameter associated with the client's verifier
         * @param v The client's verifier
         * @param digest The digest algorithm associated with the client's verifier
         * @param random For key generation
         */
        public virtual void Init(BigInteger N, BigInteger g, BigInteger v, IDigest digest, SecureRandom random)
        {
            if (N is null)
            {
                throw new ArgumentNullException(nameof(N));
            }

            if (g is null)
            {
                throw new ArgumentNullException(nameof(g));
            }

            if (v is null)
            {
                throw new ArgumentNullException(nameof(v));
            }

            if (digest is null)
            {
                throw new ArgumentNullException(nameof(digest));
            }

            if (random is null)
            {
                throw new ArgumentNullException(nameof(random));
            }

            this.N = N;
            this.g = g;
            this.v = v;

            this.random = random;
            this.digest = digest;
        }

        /// <summary>
        /// Initialises the server to accept a new client authentication attempt.
        /// </summary>
        public virtual void Init(Srp6GroupParameters group, BigInteger v, IDigest digest, SecureRandom random)
        {
            if (group is null)
            {
                throw new ArgumentNullException(nameof(group));
            }

            if (v is null)
            {
                throw new ArgumentNullException(nameof(v));
            }

            if (digest is null)
            {
                throw new ArgumentNullException(nameof(digest));
            }

            if (random is null)
            {
                throw new ArgumentNullException(nameof(random));
            }

            Init(group.N, group.G, v, digest, random);
        }

        /// <summary>
        /// Initialises the server to accept a new client authentication attempt with some specific params:
        /// generator = 2, IDigest is a new ExtendedHashDigest(), SecureRandom is a new SecureRandom().
        /// </summary>
        /// <param name="base64N">Modulus N.</param>
        /// <param name="v">Verifier value.</param>
        /// <exception cref="ArgumentException"></exception>
        public virtual void SimpleInit(string base64N, BigInteger v)
        {
            if (string.IsNullOrEmpty(base64N))
            {
                throw new ArgumentException("Parameter can not be null or empty", nameof(base64N));
            }

            if (v is null)
            {
                throw new ArgumentNullException(nameof(v));
            }

            var decodedBase64N = Base64.Decode(base64N);
            BigInteger N = new BigInteger(1, decodedBase64N.Reverse().ToArray());
            BigInteger g = new BigInteger("2");
            Init(N, g, v, new ExtendedHashDigest(), new SecureRandom());
        }

        /**
         * Generates the server's credentials that are to be sent to the client.
         * @return The server's public value to the client
         */
        public virtual BigInteger GenerateServerCredentials()
        {
            BigInteger k = ProtonSRPUtilities.CalculateK(digest, g, N);
            this.privB = SelectPrivateValue();
            this.pubB = k.Multiply(v).Mod(N).Add(g.ModPow(privB, N)).Mod(N);

            return pubB;
        }

        /**
         * Processes the client's credentials. If valid the shared secret is generated and returned.
         * @param clientA The client's credentials
         * @return A shared secret BigInteger
         * @throws CryptoException If client's credentials are invalid
         */
        public virtual BigInteger CalculateSecret(BigInteger clientA)
        {
            this.A = ProtonSRPUtilities.ValidatePublicValue(N, clientA);
            this.u = ProtonSRPUtilities.CalculateU(digest, N, A, pubB);
            this.S = CalculateS();

            return S;
        }

        protected virtual BigInteger SelectPrivateValue()
        {
            return ProtonSRPUtilities.GeneratePrivateValue(digest, N, g, random);
        }

        private BigInteger CalculateS()
        {
            var basement = v.ModPow(u, N).Multiply(A).Mod(N);
            return basement.ModPow(privB, N);
        }

        /** 
         * Authenticates the received client evidence message M1 and saves it only if correct.
         * To be called after calculating the secret S.
         * @param M1: the client side generated evidence message
         * @return A boolean indicating if the client message M1 was the expected one.
         * @throws CryptoException 
         */
        public virtual bool VerifyClientEvidenceMessage(BigInteger clientM1)
        {
            // Verify pre-requirements
            if (this.A == null || this.pubB == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute and verify M1: " +
                        "some data are missing from the previous operations (A,B,S)");
            }

            // Compute the own client evidence message 'M1'
            BigInteger computedM1 = ProtonSRPUtilities.CalculateM1(digest, N, A, pubB, S);
            if (computedM1.Equals(clientM1))
            {
                this.M1 = clientM1;
                return true;
            }
            return false;
        }

        /**
         * Computes the server evidence message M2 using the previously verified values.
         * To be called after successfully verifying the client evidence message M1.
         * @return M2: the server side generated evidence message
         * @throws CryptoException
         */
        public virtual BigInteger CalculateServerEvidenceMessage()
        {
            // Verify pre-requirements
            if (this.A == null || this.M1 == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute M2: " +
                        "some data are missing from the previous operations (A,M1,S)");
            }

            // Compute the server evidence message 'M2'
            this.M2 = ProtonSRPUtilities.CalculateM2(digest, N, A, M1, S);
            return M2;
        }

        /**
         * Computes the final session key as a result of the SRP successful mutual authentication
         * To be called after calculating the server evidence message M2.
         * @return Key: the mutual authenticated symmetric session key
         * @throws CryptoException
         */
        public virtual BigInteger CalculateSessionKey()
        {
            // Verify pre-requirements
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
