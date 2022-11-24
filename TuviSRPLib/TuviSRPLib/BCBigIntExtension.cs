using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TuviSRPLib
{
    public static class BCBigIntExtension
    {
        /// <summary>
        /// Converting BC.BigInteger into byte array with low-endian format.
        /// </summary>
        /// <param name="number">BigInteger number.</param>
        /// <returns>Byte array with big-endian format.</returns>
        public static byte[] ToLowEndianByteArray(this BigInteger number)
        {
            return number.ToByteArrayUnsigned().Reverse().ToArray();
        }

        /// <summary>
        /// Converting BC.BigInteger into N-byte array with low-endian format. Default N = 256.
        /// </summary>
        /// <param name="number">BigInt number.</param>
        /// <param name="N">Amount of bytes.</param>
        /// <returns>Byte array.</returns>
        public static byte[] ToLowEndianNByteArray(this BigInteger number, int N = 256)
        {
            byte[] bytes = new byte[N];
            byte[] numberBytes = number.ToByteArrayUnsigned();

            for (int i = 0; i < numberBytes.Length; i++)
            {
                bytes[i] = numberBytes[numberBytes.Length - 1 - i];
            }

            return bytes;
        }
    }
}
