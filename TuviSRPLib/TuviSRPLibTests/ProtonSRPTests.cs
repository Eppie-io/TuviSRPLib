using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Encoders;
using ProtonBase64Lib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using TuviSRPLib;

namespace TuviSRPLibTests
{
    internal class ProtonSRPTests
    {
        [Test]
        public void FullCycleOfWorkTest()
        {
            //var group = Srp6StandardGroups.rfc5054_1024;

            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(decodedN);
            BigInteger g = new BigInteger("2");

            string identity = "ivanov";
            string password = "qwerty";
            string salt = "some bytes";

            Encoding enc = Encoding.UTF8;
            byte[] identityBytes = enc.GetBytes(identity);
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = enc.GetBytes(salt);

            ProtonSRPClient client = new ProtonSRPClient();
            ProtonSRPServer server = new ProtonSRPServer();
            IDigest digest = new ExtendedHashDigest();
            //ProtonDigest digest = new ProtonDigest();
            //Sha512Digest digest = new Sha512Digest();
            //Sha1Digest digest = new Sha1Digest();

            var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, identityBytes, passwordBytes);

            server.Init(N, g, verifier, digest, new SecureRandom());
            client.Init(N, g, digest, new SecureRandom());

            BigInteger pubA = client.GenerateClientCredentials(saltBytes, identityBytes, passwordBytes);
            BigInteger pubB = server.GenerateServerCredentials();

            BigInteger serverSecret = server.CalculateSecret(pubA);
            BigInteger clientSecret = client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            server.VerifyClientEvidenceMessage(M1);
            Assert.IsTrue(server.VerifyClientEvidenceMessage(M1), "Message M1 is not verified.");

            BigInteger M2 = server.CalculateServerEvidenceMessage();

            Assert.IsTrue(client.VerifyServerEvidenceMessage(M2), "Message M2 is not verified.");

            BigInteger clientKey = client.CalculateSessionKey();
            BigInteger serverKey = server.CalculateSessionKey();

            Assert.AreEqual(clientKey, serverKey);
        }

        [Test]
        public void LowClientSideWorkTest()
        {
            //pubB
            string testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
            var decodedPubB = Base64.Decode(testServerEphemeral);
            BigInteger pubB = new BigInteger(1, decodedPubB.Reverse().ToArray());

            //M2
            string testServerProof = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g==";
            var decodedExpectedM2 = Base64.Decode(testServerProof);
            BigInteger expectedM2 = new BigInteger(1, decodedExpectedM2.Reverse().ToArray());

            //M1
            string testClientProof = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==";
            var decodedExpectedM1 = Base64.Decode(testClientProof);
            BigInteger expectedM1 = new BigInteger(1, decodedExpectedM1.Reverse().ToArray());

            //N and g
            var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
            var decodedN = Base64.Decode(encodedN);
            BigInteger N = new BigInteger(1, decodedN.Reverse().ToArray());
            //var revDecN = decodedN.Reverse().ToArray();
            //BigInteger reversedN = new BigInteger(1, decodedN.Reverse().ToArray());

            //System.Numerics.BigInteger N4 = new System.Numerics.BigInteger(decodedN,false,false);
            //byte[] newBytes = ProtonSRPUtilities.ProtonReverseConverting(decodedN);
            //BigInteger N2 = new BigInteger(1, newBytes);

            //ulong[] longArray = new ulong[] { 13892194841939841713, 7741667040519877818, 15330558805459657559, 5298845592611733774, 391311890767024225, 4541256952080141867, 6590088834882493991, 8207694472128873050, 13116692135977688176, 61587140368099628, 18374051013761468385, 12572858152805685010, 10919800886130033907, 12268727164268054038, 5841320736752177212, 1948844427910546087, 9762772073895348110, 1431329582691004066, 18310769576652935084, 13439936357728160847, 16689860546079706332, 11416487501782879873, 2158624007889457114, 594301236677444276, 9519144927223285592, 918969706655286581, 8794579677818365275, 16129531347449584481, 3764607666255404370, 6563016733278980569, 10933507667870804127, 6020327087085502235 };
            //var privateA = StringFronULongArray(longArray);


            //byte[] bts = new byte[] { 15, 28, 144 };
            //BigInteger bigbts = new BigInteger(1, bts);
            //byte[] btaBytes = bigbts.ToByteArrayUnsigned();

         
            //byte[] newBytes = decodedN.Reverse().ToArray();
            //BigInteger N2 = new BigInteger(newBytes);
            //BigInteger N3 = new BigInteger(1, newBytes);

            BigInteger g = new BigInteger("2");

            string identity = "jakubqa";
            string password = "abc123";
            string salt = "yKlc5/CvObfoiw==";
            string prA = "10547061652029274211379670715837497191923711392100181473801853905808809915196907607203711902581702530909229913139029064200053653545356956180378507124271109459013112604023928943361222711612802880534999338627841076012785708089125889096845658736374227261674415889530408226129007272971994571573711799978768722905740355338656395674139700290418014119543614116447579043620139396281282725306429481228395234306648949282792144922413465416627055298443842406176782173942480534905749407414063778620271297106813842950024831635672697955431839334459563366906834842208162136118219911675083220520501587197458892001573436641639539315377";
            //string privateA = "1389219484193984171377416670405198778181533055880545965755952988455926117337743913118907670242254541256952080141867659008883488249399182076944721288730501311669213597768817661587140368099628183740510137614683851257285815280568501010919800886130033907122687271642680540385841320736752177212194884442791054608797627720738953481101431329582691004066183107695766529350841343993635772816084716689860546079706332114164875017828798732158624007889457114594301236677444276951914492722328559291896970665528658187945796778183652751612953134744958448137646076662554043706563016733278980569109335076678708041276020327087085502235";
            BigInteger privA = new BigInteger(prA);
            //byte[] prABytes = privA.ToByteArrayUnsigned();
            //BigInteger reversedPrivA = new BigInteger(1, prABytes.Reverse().ToArray());

            Encoding enc = Encoding.UTF8;
            byte[] identityBytes = enc.GetBytes(identity);
            byte[] passwordBytes = enc.GetBytes(password);
            byte[] saltBytes = Base64.Decode(salt);
            //string encryptedSaltWithProton = "wIja39AtMZdmg1/wZ1PtZe==";
            //byte[] encSaltBytes = Base64.Decode(encryptedSaltWithProton);

            ProtonSRPClient client = new ProtonSRPClient();
            //ProtonSRPServer server = new ProtonSRPServer();
            IDigest digest = new ExtendedHashDigest();
            //ProtonDigest digest = new ProtonDigest();
            //Sha512Digest digest = new Sha512Digest();
            //Sha1Digest digest = new Sha1Digest();

            //client.Init(N, g, digest, new SecureRandom());

            //BigInteger pubA = client.GenerateClientCredentials(saltBytes, identityBytes, passwordBytes);

            var pubA = client.InitAndGenerateCredential(N, /*N,*/ g, digest, new SecureRandom(), privA, saltBytes, identityBytes, passwordBytes);
            //byte[] pubABytes = pubA.ToByteArrayUnsigned();
            BigInteger clientSecret = client.CalculateSecret(pubB);

            BigInteger M1 = client.CalculateClientEvidenceMessage();
            Assert.AreEqual(expectedM1, M1);

            Assert.IsTrue(client.VerifyServerEvidenceMessage(expectedM2), "Message M2 is not verified.");


            //var verifier = ProtonSRPUtilities.CalculateVerifier(digest, N, g, saltBytes, identityBytes, passwordBytes);

            //server.Init(N, g, verifier, digest, new SecureRandom());
            client.Init(N, g, digest, new SecureRandom());

            //BigInteger pubA = client.GenerateClientCredentials(saltBytes, identityBytes, passwordBytes);
            //BigInteger pubB = server.GenerateServerCredentials();

            //BigInteger serverSecret = server.CalculateSecret(pubA);
            //BigInteger clientSecret = client.CalculateSecret(pubB);

            //BigInteger M1 = client.CalculateClientEvidenceMessage();
            //server.VerifyClientEvidenceMessage(M1);
            //Assert.IsTrue(server.VerifyClientEvidenceMessage(M1), "Message M1 is not verified.");

            //BigInteger M2 = server.CalculateServerEvidenceMessage();

            //Assert.IsTrue(client.VerifyServerEvidenceMessage(M2), "Message M2 is not verified.");

            //BigInteger clientKey = client.CalculateSessionKey();
            //BigInteger serverKey = server.CalculateSessionKey();

            //Assert.AreEqual(clientKey, serverKey);

        }

        //[Test]
        //public void ClientSideWorkTest()
        //{
        //    //pubB
        //    string testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
        //    var decodedPubB = Base64.Decode(testServerEphemeral);
        //    BigInteger pubB = new BigInteger(1, decodedPubB);
            
        //    //M2
        //    string testServerProof = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g==";
        //    var decodedExpectedM2 = Base64.Decode(testServerProof);
        //    BigInteger expectedM2 = new BigInteger(1, decodedExpectedM2);

        //    //M1
        //    string testClientProof = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==";
        //    var decodedExpectedM1 = Base64.Decode(testClientProof);
        //    BigInteger expectedM1 = new BigInteger(1, decodedExpectedM1);

        //    //N and g
        //    var encodedN = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
        //    var decodedN = Base64.Decode(encodedN);
        //    BigInteger N = new BigInteger(1, decodedN);
        //    BigInteger reversedN = new BigInteger(1, decodedN.Reverse().ToArray());
            
        //    BigInteger g = new BigInteger("2");

        //    string identity = "jakubqa";
        //    string password = "abc123";
        //    string salt = "yKlc5/CvObfoiw==";
        //    string prA = "10547061652029274211379670715837497191923711392100181473801853905808809915196907607203711902581702530909229913139029064200053653545356956180378507124271109459013112604023928943361222711612802880534999338627841076012785708089125889096845658736374227261674415889530408226129007272971994571573711799978768722905740355338656395674139700290418014119543614116447579043620139396281282725306429481228395234306648949282792144922413465416627055298443842406176782173942480534905749407414063778620271297106813842950024831635672697955431839334459563366906834842208162136118219911675083220520501587197458892001573436641639539315377";
        //    BigInteger privA = new BigInteger(prA);
            
        //    Encoding enc = Encoding.UTF8;
        //    byte[] identityBytes = enc.GetBytes(identity);
        //    byte[] passwordBytes = enc.GetBytes(password);
        //    byte[] saltBytes = Base64.Decode(salt);

        //    ProtonSRPClient client = new ProtonSRPClient();
        //    IDigest digest = new ExtendedHashDigest();
            
        //    var pubA = client.InitAndGenerateCredential(N, reversedN, g, digest, new SecureRandom(), privA, saltBytes, identityBytes, passwordBytes);
        //    byte[] pubABytes = pubA.ToByteArrayUnsigned();
        //    BigInteger clientSecret = client.CalculateSecret(pubB);

        //    BigInteger M1 = client.CalculateClientEvidenceMessage();
        //    Assert.AreEqual(expectedM1, M1);

        //    Assert.IsTrue(client.VerifyServerEvidenceMessage(expectedM2), "Message M2 is not verified.");

        //    client.Init(N, g, digest, new SecureRandom());
        //}

        private string StringFronULongArray(ulong[] array)
        {
            System.Numerics.BigInteger number = new System.Numerics.BigInteger(0);
            
            for (int i = array.Length - 1; i >= 0; i--)
            {
                byte[] ulongBytes = ULongToBytes(array[i]);
                for (int k = 0; k < ulongBytes.Length; k++)
                {
                    number = number << 8;
                    number |= ulongBytes[k];
                }
                //number = number << 64;
                //number |= array[i];
            }
            return number.ToString();
        }

        private byte[] ULongToBytes(ulong num)
        {
            ulong temp = num;
            List<byte> result = new List<byte>();
            for (int i = 0; i < 8; i++)
            {
                byte currentByte = (byte)(temp & 255);
                result.Add(currentByte);
                temp = temp >> 8;
            }

            //result.Reverse();
            return result.ToArray();
        }

        [Test]
        public void Test2()
        {
            byte[] output = new byte[] { 12, 34, 56, 78 };
            BigInteger N = new BigInteger(1, output);


            System.Numerics.BigInteger bitSequence = new System.Numerics.BigInteger(0);
            bitSequence = bitSequence.BigEndianConcatBytes(output);

            int paddedLength = (N.BitLength + 7) / 8;
            byte[] bytes = new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(N, bytes, 0, bytes.Length);

            bytes.CopyTo(bytes, 0);
            //string salt1 = "xTRjm6MUl5mpYA==";
            //string salt2 = "CGhrAMJla9YHGQ==";
            //var res1 = Base64.Decode(salt1);
            //var res2 = Base64.Decode(salt2);

            //string salt = "some salt";

            //Encoding enc = Encoding.UTF8;
            //byte[] identityBytes = enc.GetBytes(salt);

            

            byte[] numBytes = new byte[] { 1, 10 };
            
            System.Numerics.BigInteger num = new System.Numerics.BigInteger(numBytes, true, true); // 266 - BigEndian
            System.Numerics.BigInteger num2 = new System.Numerics.BigInteger(numBytes, true, false); // 2561 - LowEndian

            Assert.Pass();
        }

        [Test]
        public void Test3()
        {
            string salt1 = "xTRjm6MUl5mpYA==";
            string salt2 = "CGhrAMJla9YHGQ==";
            var res1 = Base64.Decode(salt1);
            var res2 = Base64.Decode(salt2);

            string salt = "some salt";

            Encoding enc = Encoding.UTF8;
            byte[] identityBytes = enc.GetBytes(salt);

            Assert.Pass();
        }
    }
}
