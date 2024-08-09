using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using ProtonBase64Lib;
using System;
using System.Linq;
using System.Text;
using TuviSRPLib.Utils;

namespace TuviSRPLib
{
    /// <summary>
    /// Implements the utilities (calculations) used for SRP protocol proton edition. Based on the BouncyCastle lib
    /// https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/agreement/srp/SRP6Utilities.cs
    /// Proton SRP protocol doesn't use UserName(Identity) calculating Verifier.
    /// </summary>
    public static class ProtonSRPUtilities
    {
        private const int Cost = 10; // it shows how many reps(cycles) bcrypt will do during calculations (2^cost times)
        private const int SaltLen = 16; // bcrypt requirement
        /// <summary>
        /// Calculates value of multiplier K.
        /// </summary>
        /// <param name="digest">Digest (hash algorithm).</param>
        /// <param name="g">Field generator.</param>
        /// <param name="N">Field order.</param>
        /// <returns>Multiplier value.</returns>
        public static BigInteger CalculateK(IDigest digest, BigInteger g, BigInteger N)
        {
            return HashPaddedPair(digest, N, g, N);
        }

        /// <summary>
        /// Calculates parameter U or ScrambleParam in Proton realization.
        /// </summary>
        /// <param name="digest">Digest (hash algorithm).</param>
        /// <param name="N">Field order.</param>
        /// <param name="A">Client's public value.</param>
        /// <param name="B">Server's public value.</param>
        /// <returns>U value.</returns>
        public static BigInteger CalculateU(IDigest digest, BigInteger N, BigInteger A, BigInteger B)
        {
            return HashPaddedPair(digest, N, A, B);
        }

        /// <summary>
        /// Calculates parameter X or HashedPassword in Proton realization.
        /// Proton SRP protocol doesn't use UserName(Identity) calculating Verifier.
        /// </summary>
        /// <param name="digest">Digest (hash algorithm).</param>
        /// <param name="N">Field order.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="password">Password.</param>
        /// <returns>X value.</returns>
        public static BigInteger CalculateX(IDigest digest, BigInteger N, byte[] salt, byte[] password)
        {
            if (salt.Length < 10)
            {
                throw new ArgumentException($"`salt` is shorter than 10 bytes");
            }
            int paddedLength = (N.BitLength + 7) / 8;
            byte[] output = new byte[digest.GetDigestSize()];
            Encoding enc = Encoding.UTF8;
            byte[] byteProton = enc.GetBytes("proton"); // Proton protocol appends (salt + "proton") before calculation
            var extSalt = Append(salt, byteProton); // Function hashPasswordVersion3, file https://github.com/ProtonMail/go-srp/blob/master/hash.go, row 111

            byte[] message = GetMailboxPassword(password, extSalt);
            BlockUpdateUnified(digest, message);

            byte[] bytes = N.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            DoFinalUnified(digest, output);
            return new BigInteger(1, output.Reverse().ToArray());
        }

        public static byte[] GetMailboxPassword(byte[] password, byte[] salt)
        {
            // Note: About the 'password' parameter
            //
            // The BouncyCastle 'Bcrypt' (BCrypt.Generate) algorithm has a strict limitation of
            // no more than 72 bytes for the 'password' parameter size.
            // However, the ProtonMail 'Bcrypt' algorithm has no limitation and allows the 'password'
            // parameter size to be larger than 72 bytes. Despite this, it also uses 72 bytes
            // according to the specification which requires initialization with 18 32-bit subkeys.
            // This comes from the 'Eksblowfish' algorithm which is the first phases of the 'Bcrypt'.
            //
            // Therefore, the 'password' parameter must be truncated to the first 72 bytes.
            //
            // See: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf
            // See: https://github.com/ProtonMail/bcrypt/blob/master/bcrypt.go#L110 (func: HashBytes)

            const int MaxPasswordBytes = 72;

            var newPassword = Append(password, new byte[] { 0 }); // Function HashBytes, file https://github.com/ProtonMail/bcrypt/blob/master/bcrypt.go, row 173

            if (password.Length >= MaxPasswordBytes)
            {
                newPassword = password.Take(MaxPasswordBytes).ToArray();
            }

            var hashedPassword = BCrypt.Generate(newPassword, salt.AsSpan(0, SaltLen).ToArray(), Cost); // Function HashBytes, file https://github.com/ProtonMail/bcrypt/blob/master/bcrypt.go, row 176
            return FormBcryptString(salt, hashedPassword);
        }

        /// <summary>
        /// Forming special sequence of bytes used in proton protocol.
        /// </summary>
        /// <param name="extSalt">Extended salt (salt + "proton").</param>
        /// <param name="hashedPassword">Hashed password (bcrypt algorithm).</param>
        /// <returns>Byte sequence.</returns>
        private static byte[] FormBcryptString(byte[] extSalt, byte[] hashedPassword)
        {
            // TODO: create dynamic prefix according to proton realization?
            // Function build_bcrypt_str in https://github.com/ProtonMail/bcrypt/blob/master/bcrypt.go
            // creates prefix before salt. But in all visible cases only "$2y$10$" prefix is used:
            byte[] prefix = new byte[] { 36, 50, 121, 36, 49, 48, 36 }; // "$2y$10$"

            var addSalt = ProtonBase64.Encode(extSalt);
            var shortenedPassword = hashedPassword.AsSpan(0, hashedPassword.Length - 1).ToArray();
            var addPass = ProtonBase64.Encode(shortenedPassword);
            return Append(Append(prefix, addSalt.AsSpan(0, 22).ToArray()), addPass); // Function HashBytes, file https://github.com/ProtonMail/bcrypt/blob/master/bcrypt.go, row 159
        }

        /// <summary>
        /// Calculates verifier V.
        /// Proton SRP protocol doesn't use UserName(Identity) calculating Verifier.
        /// </summary>
        /// <param name="digest">Digest (hash algorithm).</param>
        /// <param name="N">Field order.</param>
        /// <param name="g">Field generator.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="password">Password.</param>
        /// <returns>Verifier value.</returns>
        public static BigInteger CalculateVerifier(IDigest digest, BigInteger N, BigInteger g, byte[] salt, byte[] password)
        {
            var x = CalculateX(digest, N, salt, password);
            return g.ModPow(x, N);
        }

        public static BigInteger GeneratePrivateValue(IDigest digest, BigInteger N, BigInteger g, SecureRandom random)
        {
            int minBits = System.Math.Min(256, N.BitLength / 2);
            BigInteger min = BigInteger.One.ShiftLeft(minBits - 1);
            BigInteger max = N.Subtract(BigInteger.One);

            return BigIntegers.CreateRandomInRange(min, max, random);
        }

        public static BigInteger ValidatePublicValue(BigInteger N, BigInteger val)
        {
            val = val.Mod(N);

            // Check that val % N != 0
            if (val.Equals(BigInteger.Zero))
                throw new CryptoException("Invalid public value: 0");

            return val;
        }

        /** 
         * Computes the client evidence message (M1) according to the standard routine:
         * M1 = H( A | B | S )
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param A The public client value
         * @param B The public server value
         * @param S The secret calculated by both sides
         * @return M1 The calculated client evidence message
         */
        public static BigInteger CalculateM1(IDigest digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S)
        {
            BigInteger M1 = HashPaddedTriplet(digest, N, A, B, S);
            return M1;
        }

        /** 
         * Computes the server evidence message (M2) according to the standard routine:
         * M2 = H( A | M1 | S )
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param A The public client value
         * @param M1 The client evidence message
         * @param S The secret calculated by both sides
         * @return M2 The calculated server evidence message
         */
        public static BigInteger CalculateM2(IDigest digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S)
        {
            BigInteger M2 = HashPaddedTriplet(digest, N, A, M1, S);
            return M2;
        }

        /**
         * Computes the final Key according to the standard routine: Key = H(S)
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param S The secret calculated by both sides
         * @return
         */
        public static BigInteger CalculateKey(IDigest digest, BigInteger N, BigInteger S)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

            byte[] bytes = S.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            byte[] output = new byte[digestSize];
            DoFinalUnified(digest, output);
            return new BigInteger(1, output.Reverse().ToArray());
        }

        private static BigInteger HashPaddedTriplet(IDigest digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

            byte[] bytes = n1.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            bytes = n2.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            bytes = n3.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            byte[] output = new byte[digestSize];
            DoFinalUnified(digest, output);
            return new BigInteger(1, output.Reverse().ToArray());
        }

        private static BigInteger HashPaddedPair(IDigest digest, BigInteger N, BigInteger n1, BigInteger n2)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

            byte[] bytes = n1.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);
            bytes = n2.ToLowEndianNByteArray(paddedLength);
            BlockUpdateUnified(digest, bytes);

            byte[] output = new byte[digestSize];
            DoFinalUnified(digest, output);
            return new BigInteger(1, output.Reverse().ToArray());
        }

        private static void BlockUpdateUnified(IDigest digest, byte[] bytes)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            digest.BlockUpdate(bytes);
#else
            digest.BlockUpdate(bytes, 0, bytes.Length);
#endif
        }

        private static void DoFinalUnified(IDigest digest, byte[] output)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            digest.DoFinal(output);
#else
            digest.DoFinal(output, 0);
#endif
        }

        private static byte[] Append(byte[] arr1, byte[] arr2)
        {
            return arr1.Concat(arr2).ToArray();
        }
    }
}
