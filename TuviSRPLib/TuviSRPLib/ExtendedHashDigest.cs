using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace TuviSRPLib
{
    /// <summary>
    /// Extended hash algorithm used in Proton protocol.
    /// </summary>
    public class ExtendedHashDigest : IDigest
    {
        private byte[] _buffer;
        private int _capacity;
        private int _currentSize;
        private const int DigestLength = 256;

        public ExtendedHashDigest()
        {
            _capacity = 512;
            _currentSize = 0;
            _buffer = new byte[_capacity];
            Reset();
        }

        /// <summary>
        /// Return the algorithm name.
        /// </summary>
        public string AlgorithmName => "ExtendedHash";

        /// <summary>
        /// Update the message digest with a block of bytes.
        /// </summary>
        /// <param name="input">The byte array containing the data.</param>
        /// <param name="inOff">The offset into the byte array where the data starts.</param>
        /// <param name="inLen">the length of the data.</param>
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            if (input is null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (inOff < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inOff), "Parameter inOff can not be negative.");
            }

            if (inLen < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inLen), "Parameter inLen can not be negative.");
            }

            if (_currentSize + inLen > _capacity)
            {
                IncreaseBufferCapacity(inLen);
            }
            Array.Copy(input, inOff, _buffer, _currentSize, inLen);
            _currentSize += inLen;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Update the message digest with a span of bytes.</summary>
        /// <param name="input">the span containing the data.</param>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (_currentSize + input.Length > _capacity)
            {
                IncreaseBufferCapacity(input.Length);                
            }
            Array.Copy(input.ToArray(), 0, _buffer, _currentSize, input.Length);
            _currentSize += input.Length;
        }
#endif

        /// <summary>
        /// Close the digest, producing the final digest value. The doFinal call leaves the digest reset.
        /// </summary>
        /// <param name="output">The array the digest is to be copied into.</param>
        /// <param name="outOff">The offset into the out array the digest is to start at.</param>
        /// <returns>Digest length.</returns>
        public int DoFinal(byte[] output, int outOff)
        {
            if (output is null)
            {
                throw new ArgumentNullException(nameof(output));
            }

            if (outOff < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outOff), "Parameter inOff can not be negative.");
            }

            var result = ExpandHash(new List<byte>(_buffer)
                    .GetRange(0, _currentSize)
                    .ToArray());
            Array.Copy(result, 0, output, outOff, result.Length);

            Reset();

            return DigestLength;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Close the digest, producing the final digest value.</summary>
        /// <remarks>This call leaves the digest reset.</remarks>
        /// <param name="output">the span the digest is to be copied into.</param>
        /// <returns>the number of bytes written</returns>
        public int DoFinal(Span<byte> output)
        {
            var result = ExpandHash(_buffer.AsSpan()[.._currentSize].ToArray());
            result.AsSpan(0, result.Length).CopyTo(output);
            Reset();

            return DigestLength;
        }
#endif

        public int GetByteLength()
        {
            return _currentSize;
        }

        public int GetDigestSize()
        {
            return DigestLength;
        }

        /// <summary>
        /// Reset all the parameters to initial values.
        /// </summary>
        public void Reset()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CryptographicOperations.ZeroMemory(_buffer);
#else
            ZeroMemory(_buffer);
#endif
            _currentSize = 0;
            _capacity = 512;
            _buffer = new byte[_capacity];
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void ZeroMemory(byte[] buffer)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Update the message digest with a single byte.
        /// </summary>
        /// <param name="input">Updating byte.</param>
        public void Update(byte input)
        {
            if (_currentSize + 1 > _capacity)
            {
                IncreaseBufferCapacity(1);
            }
            _buffer[_currentSize] = input;
            _currentSize += 1;
        }

        private void IncreaseBufferCapacity(int inLen)
        {
            do
            {
                _capacity <<= 1; // *= 2
            }
            while (_currentSize + inLen > _capacity);

            byte[] newBuffer = new byte[_capacity];
            Array.Copy(_buffer, 0, newBuffer, 0, _currentSize);
            ZeroMemory(_buffer);
            _buffer = newBuffer;
        }

        private byte[] ExpandHash(byte[] data)
        {
            var sha512 = SHA512.Create();
            byte[] tempData = new byte[data.Length + 1];
            Array.Copy(data, tempData, data.Length);
            tempData[tempData.Length - 1] = 0;
            byte[] part0 = sha512.ComputeHash(tempData);
            tempData[tempData.Length - 1] = 1;
            byte[] part1 = sha512.ComputeHash(tempData);
            tempData[tempData.Length - 1] = 2;
            byte[] part2 = sha512.ComputeHash(tempData);
            tempData[tempData.Length - 1] = 3;
            byte[] part3 = sha512.ComputeHash(tempData);
            byte[] result = new byte[64 * 4];
            Array.Copy(part0, 0, result, 0, 64);
            Array.Copy(part1, 0, result, 64, 64);
            Array.Copy(part2, 0, result, 128, 64);
            Array.Copy(part3, 0, result, 192, 64);
            ZeroMemory(tempData);
            return result;
        }
    }
}
