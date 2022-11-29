using Org.BouncyCastle.Security;

namespace TuviSRPLibTests
{
    /// <summary>
    /// Class that produce the same specific UNsecure byte sequence and is used ONLY for testing reason
    /// </summary>
    internal class MyUnsecureRandom : SecureRandom
    {
        private byte[] seed;

        private int size;

        internal MyUnsecureRandom()
        {
            string pseudoRandom = "10547061652029274211379670715837497191923711392100181473801853905808809915196907607203711902581702530909229913139029064200053653545356956180378507124271109459013112604023928943361222711612802880534999338627841076012785708089125889096845658736374227261674415889530408226129007272971994571573711799978768722905740355338656395674139700290418014119543614116447579043620139396281282725306429481228395234306648949282792144922413465416627055298443842406176782173942480534905749407414063778620271297106813842950024831635672697955431839334459563366906834842208162136118219911675083220520501587197458892001573436641639539315377";
            BigInteger rndNum = new BigInteger(pseudoRandom);
            seed = rndNum.ToByteArrayUnsigned();
            size = seed.Length;
        }

        /// <summary>
        /// Fills byte array buf with specific bytes from seed.
        /// </summary>
        /// <param name="buf">byte array that should be filled by random numbers.</param>
        public override void NextBytes(byte[] buf)
        {
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = seed[i % size];
            }
        }
    }
}
