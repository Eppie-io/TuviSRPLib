using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TuviSRPLib
{
    public class ExtendedHashDigest : IDigest
    {
        //private byte[] salt;
        private byte[] message;
        //private int cost;
        private const int DigestLength = 256;

        public ExtendedHashDigest()
        {
            Reset();
        }

        public string AlgorithmName => "ExtendedHash";

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            // TODO: add check
            byte[] newMessage = new byte[message.Length + length];
            Array.Copy(message, newMessage, message.Length);
            Array.Copy(input, inOff, newMessage, message.Length, length);
            message = newMessage;
        }

        public int DoFinal(byte[] output, int outOff)
        {
            // TODO: checks
            var result = ExpandHash(message); // Was MyBCrypt.Generate(message, salt, cost);
            Array.Copy(result, 0, output, outOff, result.Length);

            Reset();

            return DigestLength;
        }

        public int GetByteLength()
        {
            return message.Length;
        }

        public int GetDigestSize()
        {
            return DigestLength;
        }

        public void Reset()
        {
            //salt = new byte[16];
            message = new byte[0];
            //cost = 4;
            
            //byteCount = 0;
            //xBufOff = 0;
            //Array.Clear(message, 0, xBuf.Length);
        }

        public void Update(byte input)
        {
            byte[] newMessage = new byte[message.Length + 1];
            Array.Copy(message, newMessage, message.Length);
            newMessage[newMessage.Length - 1] = input;
            message = newMessage;
        }

        

        //private byte[] HashPassword(byte[]password, byte[] salt, byte[] modulus)
        //{
        //    var result = MyBCrypt.Generate(password, salt, cost);
        //    byte[] tempData = new byte[result.Length + modulus.Length];
        //    Array.Copy(result, tempData, result.Length);
        //    Array.Copy(modulus, 0, tempData, 0, modulus.Length);
        //    return ExpandHash(tempData);
        //}

        private byte[] ExpandHash(byte[] data)
        {
            //byte[] part0 = SHA512.HashData(idPassBytes);
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



        //public string AlgorithmName => throw new NotImplementedException();

        //public void BlockUpdate(byte[] input, int inOff, int length)
        //{
        //    throw new NotImplementedException();
        //}

        //public int DoFinal(byte[] output, int outOff)
        //{
        //    throw new NotImplementedException();
        //}

        //public int GetByteLength()
        //{
        //    throw new NotImplementedException();
        //}

        //public int GetDigestSize()
        //{
        //    throw new NotImplementedException();
        //}

        //public void Reset()
        //{
        //    throw new NotImplementedException();
        //}

        //public void Update(byte input)
        //{
        //    throw new NotImplementedException();
        //}
    }
}
