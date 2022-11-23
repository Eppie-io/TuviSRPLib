//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Crypto.Digests;
//using Org.BouncyCastle.Crypto.Generators;
//using Org.BouncyCastle.Utilities;
//using System;

//namespace TuviSRPLib
//{
//    //public class ProtonDigest : GeneralDigest
//    public class ProtonDigest : IDigest
//    {
//        private byte[] salt;
//        private byte[] message;
//        private int cost;
//        private const int DigestLength = 24;
//        //private long byteCount;

//        public ProtonDigest()
//        {
//            Reset();
//        }

//        //public ProtonDigest(ProtonDigest t)
//        //    : base(t)
//        //{
//        //    CopyIn(t);
//        //}

//        public string AlgorithmName => "Bcrypt";

//        public void BlockUpdate(byte[] input, int inOff, int length)
//        {
//            // TODO: add check
//            byte[] newMessage = new byte[message.Length + length];
//            Array.Copy(message, newMessage, message.Length);
//            Array.Copy(input, inOff, newMessage, message.Length, length);
//            message = newMessage;
//        }

//        public int DoFinal(byte[] output, int outOff)
//        {
//            // TODO: checks
//            var result = MyBCrypt.Generate(message, salt, cost);
//            Array.Copy(result, 0, output, outOff, result.Length);

//            Reset();

//            return DigestLength;
//        }

//        public int GetByteLength()
//        {
//            return message.Length;
//        }

//        public int GetDigestSize()
//        {
//            return DigestLength;
//        }

//        public void Reset()
//        {
//            salt = new byte[16];
//            message = new byte[0];
//            cost = 4;
//            //byteCount = 0;
//            //xBufOff = 0;
//            //Array.Clear(message, 0, xBuf.Length);
//        }

//        public void Update(byte input)
//        {
//            byte[] newMessage = new byte[message.Length + 1];
//            Array.Copy(message, newMessage, message.Length);
//            newMessage[newMessage.Length - 1] = input;
//            message = newMessage;
//        }

//        //private void CopyIn(ProtonDigest t)
//        //{
//        //    //base.CopyIn(t);

//        //    //H1 = t.H1;
//        //    //H2 = t.H2;
//        //    //H3 = t.H3;
//        //    //H4 = t.H4;
//        //    //H5 = t.H5;

//        //    //Array.Copy(t.X, 0, X, 0, t.X.Length);
//        //    //xOff = t.xOff;
//        //}

//        //public override string AlgorithmName => "Bcrypt";

//        //public override IMemoable Copy()
//        //{
//        //    return new ProtonDigest(this);
//        //    throw new NotImplementedException();
//        //}
                
//    }
//}
