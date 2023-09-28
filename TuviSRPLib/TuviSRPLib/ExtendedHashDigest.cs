using Org.BouncyCastle.Crypto;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace TuviSRPLib
{
    /// <summary>
    /// Extended hash algorithm used in Proton protocol.
    /// </summary>
    public class ExtendedHashDigest : IDigest
    {
        private byte[] _message;
        private const int DigestLength = 256;

        public ExtendedHashDigest()
        {
            _message = new byte[DigestLength];
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

            Array.Resize(ref _message, _message.Length + input.Length);
            Array.Copy(input.ToArray(), 0, _message, _message.Length - input.Length, input.Length);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Update the message digest with a span of bytes.</summary>
        /// <param name="input">the span containing the data.</param>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            Array.Resize(ref _message, _message.Length + input.Length);
            Array.Copy(input.ToArray(), 0, _message, _message.Length - input.Length, input.Length);
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

            var result = ExpandHash(_message);
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
            var result = ExpandHash(_message);
            result.AsSpan(0, result.Length).CopyTo(output);
            Reset();

            return DigestLength;
        }
#endif

        public int GetByteLength()
        {
            return _message.Length;
        }

        public int GetDigestSize()
        {
            return DigestLength;
        }

        public void Reset()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CryptographicOperations.ZeroMemory(_message);
#else
            ZeroMemory(_message);
#endif
            _message = Array.Empty<byte>();
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void ZeroMemory(byte[] buffer)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }

//        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
//        public void Reset()
//        {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
//            CryptographicOperations.ZeroMemory(_message);
//#else
//            Array.Clear(_message, 0, _message.Length);
//#endif
//            _message = Array.Empty<byte>();
//        }

        /// <summary>
        /// Update the message digest with a single byte.
        /// </summary>
        /// <param name="input">Updating byte.</param>
        public void Update(byte input)
        {
            byte[] newMessage = new byte[_message.Length + 1];
            Array.Copy(_message, newMessage, _message.Length);
            newMessage[newMessage.Length - 1] = input;
            _message = newMessage;
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
            return result;
        }
    }
}
