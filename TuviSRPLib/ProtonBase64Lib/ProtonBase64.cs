using System;
using System.Numerics;
using System.Text;

namespace ProtonBase64Lib
{
    /// <summary>
    /// Base64 algorithm with dictionary used in Proton SRP protocol.
    /// </summary>
    public static class ProtonBase64
    {
        /// <summary>
        /// Current Base64 algorithm tramsforms bytes(8-bits) sequence into 6-bits sequence. 
        /// Then converts 6-bits elements into symbols of choosen dictionary.
        /// So, to calculate size of this sequences we need following parameters:
        /// </summary>
        private const int BaseValue = 64;
        private const int SourceElementBitSize = 8; // byte size
        private const int TargetElementBitSize = 6; // log2(64) - size of Base64 chunks
        private const string ProtonBase64Dictionary = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>
        /// Encode byte array into a Base64 string.
        /// </summary>
        /// <param name="array">Original byte array.</param>
        /// <returns>Encoded Base64 string.</returns>
        public static string ToBase64String(byte[] array)
        {
            if (array is null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if (array.Length < 1)
            {
                throw new ArgumentException("Array should contain at least 1 element.");
            }

            byte[] sixBitsArray = ConvertEightToSixBits(array);
            char[] symbolsArray = new char[sixBitsArray.Length];
            for (int i = 0; i < symbolsArray.Length; i++)
            {
                symbolsArray[i] = ConvertByteToSymbol(sixBitsArray[i]);
            }
            return new string(symbolsArray);
        }
        
        /// <summary>
        /// Encode the input data producing a base 64 encoded byte array.
        /// </summary>
        /// <param name="array">Original byte array.</param>
        /// <returns>Byte array containing the base 64 encoded data.</returns>
        public static byte[] Encode(byte[] array)
        {
            if (array is null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if (array.Length < 1)
            {
                throw new ArgumentException("Array should contain at least 1 element.");
            }

            string s = ToBase64String(array);
            Encoding enc = Encoding.UTF8;
            return enc.GetBytes(s);
        }

        /// <summary>
        /// Decode Base64 string into a byte array.
        /// </summary>
        /// <param name="base64String">String of allowed symbols.</param>
        /// <returns>Array of bytes.</returns>
        public static byte[] Decode(string base64String)
        {
            if (base64String is null)
            {
                throw new ArgumentNullException(nameof(base64String));
            }

            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException("Email's name can not be empty or whitespace.");
            }

            char[] symbolsArray = base64String.ToCharArray();
            byte[] sixBitsArray = new byte[symbolsArray.Length];

            for (int i = 0; i < sixBitsArray.Length; i++)
            {
                sixBitsArray[i] = ConvertSymbolToBits(symbolsArray[i]);
            }

            return ConvertSixToEightBits(sixBitsArray);
        }

        /// <summary>
        /// Divides sequence of bits (original array) into groups of 6 bits.
        /// </summary>
        /// <param name="array">Original array.</param>
        /// <returns>Array of 6-bit groups.</returns>
        private static byte[] ConvertEightToSixBits(byte[] array)
        {
            if (array is null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if (array.Length < 1)
            {
                throw new ArgumentException("Array should contain at least 1 element.");
            }

            int remainder = array.Length * SourceElementBitSize % TargetElementBitSize;
            int size = remainder == 0 ? array.Length * SourceElementBitSize / TargetElementBitSize : array.Length * SourceElementBitSize / TargetElementBitSize + 1;
            
            int currentPosition = size - 1;
            byte[] result = new byte[size];
            BigInteger bitSequence = new BigInteger(0);
            bitSequence = bitSequence.BigEndianConcatBytes(array);

            if (remainder != 0)
            {
                bitSequence = bitSequence << (TargetElementBitSize - remainder);
            }

            while (bitSequence != 0 && currentPosition >= 0)
            {
                byte lastSixBits = (byte)(bitSequence & (BaseValue - 1));
                result[currentPosition] = lastSixBits;
                bitSequence = bitSequence >> TargetElementBitSize;
                currentPosition--;
            }

            return result;
        }

        /// <summary>
        /// Concats groups of 6 bits into a sequense. Represents it as an byte array (groups of 8 bits).
        /// </summary>
        /// <param name="array">Array of 6-bit groups.</param>
        /// <returns>Array of bytes (8-bit groups).</returns>
        private static byte[] ConvertSixToEightBits(byte[] array)
        {
            if (array is null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            BigInteger number = 0;
            int size = array.Length * TargetElementBitSize / SourceElementBitSize;
            byte[] resultArray = new byte[size];
            for (int i = 0; i < array.Length; i++)
            {
                if (array[i] >= BaseValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(array),
                        $"Array at index {i} has wrong value. Allowed values are from 0 to {BaseValue - 1}.");
                }
                number = number << TargetElementBitSize;
                number |= array[i];
            }

            int remainder = array.Length * TargetElementBitSize % SourceElementBitSize;

            number = number >> remainder; //return to original size

            byte[] tempArray = number.ToBigEndianByteArray();
            if (tempArray.Length >= resultArray.Length)
            {
                return tempArray;
            }
            else
            {
                for (int i = 1; i <= tempArray.Length; i++)
                {
                    resultArray[size - i] = tempArray[tempArray.Length - i];
                }

                return resultArray;
            }
        }

        private static char ConvertByteToSymbol(byte byteValue)
        {
            if (byteValue >= BaseValue)
            {
                throw new ArgumentOutOfRangeException(nameof(byteValue));
            }
            return ProtonBase64Dictionary[byteValue];
        }

        private static byte ConvertSymbolToBits(char symbol)
        {
            int value = ProtonBase64Dictionary.IndexOf(symbol);
            if (value == -1)
            {
                throw new ArgumentException("Wrong symbol.", nameof(symbol));
            }
            else
            {
                return (byte)value;
            }
        }
    }
}
