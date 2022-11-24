using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace TuviSRPLib
{
    /**
	 * Implements the client side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
	 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
	 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
	 */
    public class ProtonSRPClient
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
            this.N = N;
            this.g = g;
            this.digest = digest;
            this.random = random;
        }

        public virtual void Init(Srp6GroupParameters group, IDigest digest, SecureRandom random)
        {
            Init(group.N, group.G, digest, random);
        }

        /// <summary>
        /// Initialises the client to begin new authentication attempt 
        /// and generates client's credentials given the client's private key, salt, identity and password
        /// </summary>
        /// <param name="N">The safe prime associated with the client's verifier.</param>
        /// <param name="g">The group generator (always 2 for proton) associated with the client's verifier.</param>
        /// <param name="digest">The digest algorithm associated with the client's verifier.</param>
        /// <param name="random">Random for key generation.</param>
        /// <param name="privA">Private client's key.</param>
        /// <param name="salt">Client's salt.</param>
        /// <param name="identity">Client's identity.</param>
        /// <param name="password">Client's password.</param>
        /// <returns>Client's public value to send to server.</returns>
        public virtual BigInteger InitAndGenerateCredential(BigInteger N, BigInteger g, IDigest digest, SecureRandom random,
            BigInteger privA, byte[] salt, byte[] identity, byte[] password)
        {
            this.N = N;
            this.g = g;
            this.digest = digest;
            this.random = random;
            this.x = ProtonSRPUtilities.CalculateX(digest, N, salt, identity, password);
            this.privA = privA;
            this.pubA = g.ModPow(privA, N);
            return pubA;
        }

        /**
	     * Generates client's credentials given the client's salt, identity and password
	     * @param salt The salt used in the client's verifier.
	     * @param identity The user's identity (eg. username)
	     * @param password The user's password
	     * @return Client's public value to send to server
	     */
        public virtual BigInteger GenerateClientCredentials(byte[] salt, byte[] identity, byte[] password)
        {
            this.x = ProtonSRPUtilities.CalculateX(digest, N, salt, identity, password);
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
