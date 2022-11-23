using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace ProtonBase64Lib
{
    /// <summary>
    /// Extra function to work with BigInteger.
    /// </summary>
    public static class BigIntegerExtension
    {
        /// <summary>
        /// Concatenate byte array to a BigInteger number with big-endian format.
        /// Can be used as "BigInteger ctor" with big-endian format.
        /// </summary>
        /// <param name="number">Initial BigInteger.</param>
        /// <param name="array">Byte array.</param>
        /// <returns>Resulting BigInteger.</returns>
        public static BigInteger BigEndianConcatBytes(this BigInteger number, byte[] array)
        {
            for (int i = 0; i < array.Length; i++)
            {
                number = number << 8;
                number |= array[i];
            }

            return number;
        }

        /// <summary>
        /// Converting BigInteger into byte array with big-endian format.
        /// </summary>
        /// <param name="number">BigInteger number.</param>
        /// <returns>Byte array with big-endian format.</returns>
        public static byte[] ToBigEndianByteArray(this BigInteger number)
        {
            BigInteger temp = number;
            List<byte> result = new List<byte>();
            while (temp > 0)
            {
                byte currentByte = (byte)(temp & 255);
                result.Add(currentByte);
                temp = temp >> 8;
            }

            result.Reverse();
            return result.ToArray();
        }
    }
}
