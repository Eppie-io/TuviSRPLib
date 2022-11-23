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
        /// Concatenate byte array to a BC.BigInteger number with low-endian format.
        /// Can be used as "BigInteger ctor" with low-endian format.
        /// </summary>
        /// <param name="number">Initial BigInteger.</param>
        /// <param name="array">Byte array.</param>
        /// <returns>Resulting BigInteger.</returns>
        //public static BigInteger LowEndianConcatBytes(this BigInteger number, byte[] array)
        //{
        //    for (int i = array.Length -1; i >= 0; i--)
        //    {
        //        number = number.ShiftLeft(8);
        //        number = number.Or(new BigInteger(new byte[]{ array[i] }));
        //        var bytes = number.ToByteArrayUnsigned();
        //    }

        //    return number;
        //}

        /// <summary>
        /// Converting BC.BigInteger into byte array with low-endian format.
        /// </summary>
        /// <param name="number">BigInteger number.</param>
        /// <returns>Byte array with big-endian format.</returns>
        public static byte[] ToLowEndianByteArray(this BigInteger number)
        {
            return number.ToByteArrayUnsigned().Reverse().ToArray();
            //BigInteger temp = number;
            //List<byte> result = new List<byte>();
            //while (temp > 0)
            //{
            //    byte currentByte = (byte)(temp & 255);
            //    result.Add(currentByte);
            //    temp = temp >> 8;
            //}

            //result.Reverse();
            //return result.ToArray();
        }

        public static byte[] ToLowEndianNByteArray(this BigInteger number, int N = 256)
        {
            //byte[] bytes = number.ToByteArrayUnsigned();
            //BigInteger result = new BigInteger(bytes.Reverse().ToArray());
            //return result;
            byte[] bytes = new byte[N];
            byte[] numberBytes = number.ToByteArrayUnsigned();
            //BigIntegers.AsUnsignedByteArray(number, bytes, 0, bytes.Length);
            for (int i = 0; i < numberBytes.Length; i++)
            {
                bytes[i] = numberBytes[numberBytes.Length - 1 - i];
            }
            return bytes;
        }
    }
}
