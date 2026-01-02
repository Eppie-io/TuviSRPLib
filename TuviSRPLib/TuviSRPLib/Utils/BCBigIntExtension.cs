using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Linq;

namespace TuviSRPLib.Utils
{
    /// <summary>
    /// Extra functions to work with BounceCastle BigInteger.
    /// </summary>
    public static class BCBigIntExtension
    {
        /// <summary>
        /// Converting BC.BigInteger into a byte array with low-endian format.
        /// </summary>
        /// <param name="number">BigInteger number.</param>
        /// <returns>Byte array with big-endian format.</returns>
        public static byte[] ToLowEndianByteArray(this BigInteger number)
        {
            if (number is null)
            {
                throw new ArgumentNullException(nameof(number));
            }

            return number.ToByteArrayUnsigned().Reverse().ToArray();
        }

        /// <summary>
        /// Converting BC.BigInteger into the N-byte array with low-endian format. Default N = 256.
        /// </summary>
        /// <param name="number">BigInt number.</param>
        /// <param name="N">Amount of bytes.</param>
        /// <returns>Byte array.</returns>
        public static byte[] ToLowEndianNByteArray(this BigInteger number, int N = 256)
        {
            if (number is null)
            {
                throw new ArgumentNullException(nameof(number));
            }

            byte[] bytes = new byte[N];
            byte[] numberBytes = number.ToByteArrayUnsigned();

            for (int i = 0; i < Math.Min(numberBytes.Length, N); i++)
            {
                bytes[i] = numberBytes[numberBytes.Length - 1 - i];
            }

            return bytes;
        }

        /// <summary>
        /// Converting BC.BigInteger into Base64 string.
        /// </summary>
        /// <param name="number">BigInt number.</param>
        /// <returns>Base64 string.</returns>
        public static string ToBase64(this BigInteger number)
        {
            if (number is null)
            {
                throw new ArgumentNullException(nameof(number));
            }

            byte[] bytes = number.ToLowEndianByteArray();
            return Base64.ToBase64String(bytes);
        }
    }
}
