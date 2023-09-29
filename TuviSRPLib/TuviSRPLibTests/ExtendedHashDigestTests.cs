using Org.BouncyCastle.Crypto;
using TuviSRPLib;

namespace TuviSRPLibTests
{
    internal class ExtendedHashDigestTests
    {
        [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 158, 42, 204, 146, 38, 103, 162, 179, 137, 137, 151, 210, 173, 104, 114, 156, 1, 29, 188, 85, 108, 208, 0, 158, 253, 75, 210, 220, 175, 70, 74, 252, 184, 23, 18, 113, 103, 28, 58, 27, 101, 178, 225, 10, 54, 76, 144, 0, 39, 46, 243, 152, 13, 74, 92, 126, 61, 81, 97, 36, 113, 36, 207, 142, 246, 234, 91, 98, 70, 129, 86, 147, 166, 54, 173, 114, 117, 8, 93, 250, 198, 218, 249, 218, 240, 59, 14, 85, 221, 81, 25, 147, 37, 245, 38, 131, 120, 116, 6, 69, 178, 169, 176, 144, 35, 115, 12, 40, 49, 15, 118, 8, 8, 168, 152, 67, 242, 141, 163, 97, 210, 36, 213, 176, 112, 71, 193, 17, 63, 85, 118, 51, 146, 128, 106, 115, 119, 94, 149, 195, 232, 52, 241, 111, 212, 175, 137, 218, 211, 125, 110, 115, 105, 48, 31, 37, 40, 235, 19, 164, 60, 144, 234, 246, 208, 14, 32, 206, 103, 138, 10, 120, 23, 192, 60, 170, 248, 35, 124, 197, 15, 26, 189, 74, 168, 254, 146, 157, 190, 171, 66, 124, 237, 12, 121, 194, 252, 86, 192, 54, 74, 240, 162, 207, 216, 3, 161, 107, 248, 133, 47, 61, 60, 253, 157, 77, 123, 200, 12, 175, 217, 236, 96, 192, 55, 138, 163, 33, 229, 141, 251, 124, 45, 24, 52, 36, 107, 242, 243, 81, 209, 105, 187, 159, 175, 161, 211, 244, 130, 252, 193, 89, 204, 245, 182, 121 })]
        [TestCase(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, new byte[] { 200, 190, 67, 207, 99, 54, 47, 176, 188, 157, 254, 90, 248, 31, 33, 150, 143, 195, 158, 49, 136, 16, 249, 72, 22, 213, 191, 191, 141, 97, 203, 205, 143, 191, 166, 144, 5, 124, 162, 130, 22, 206, 150, 167, 223, 124, 60, 195, 3, 180, 145, 220, 186, 244, 131, 20, 92, 61, 235, 119, 217, 159, 32, 71, 15, 19, 135, 241, 252, 9, 220, 24, 166, 249, 54, 212, 178, 6, 113, 104, 235, 6, 147, 174, 49, 7, 196, 247, 216, 39, 16, 234, 118, 250, 197, 43, 154, 44, 209, 66, 175, 4, 21, 37, 184, 131, 169, 114, 254, 145, 5, 20, 69, 82, 153, 83, 168, 34, 16, 48, 14, 195, 159, 149, 153, 199, 23, 190, 47, 151, 200, 229, 89, 197, 142, 151, 122, 59, 35, 236, 125, 28, 227, 136, 68, 249, 136, 248, 142, 236, 243, 189, 122, 0, 14, 146, 166, 161, 116, 26, 108, 8, 235, 202, 49, 170, 205, 161, 253, 27, 199, 231, 60, 109, 122, 28, 66, 154, 159, 3, 113, 183, 90, 86, 253, 42, 207, 168, 123, 246, 172, 239, 44, 54, 251, 251, 157, 174, 182, 66, 49, 80, 111, 211, 177, 240, 116, 57, 51, 52, 244, 150, 211, 233, 120, 176, 165, 91, 171, 46, 65, 237, 235, 122, 227, 182, 175, 119, 199, 168, 174, 50, 125, 79, 49, 6, 204, 35, 217, 155, 11, 143, 24, 242, 219, 208, 76, 100, 142, 148, 126, 202, 195, 149, 113, 128 })]
        public void HashCalculationTest(byte[] message, byte[] expectedResult)
        {
            IDigest digest = new ExtendedHashDigest();
            digest.BlockUpdate(message, 0, message.Length);
            byte[] actualResult = new byte[256];
            digest.DoFinal(actualResult);
            
            Assert.That(actualResult, Is.EqualTo(expectedResult));
        }

        [Test]
        public void UpdateTest()
        {
            IDigest digest1 = new ExtendedHashDigest();
            digest1.BlockUpdate(new byte[] {1, 2, 3}, 0, 3);

            IDigest digest2 = new ExtendedHashDigest();
            for (byte i = 1; i <= 3; i++)
            {
                digest2.Update(i);
            }

            byte[] actualResult1 = new byte[256];
            byte[] actualResult2 = new byte[256];
            digest1.DoFinal(actualResult1);
            digest2.DoFinal(actualResult2);

            Assert.That(actualResult1, Is.EqualTo(actualResult2));
        }

        [Test]
        public void SpanBlockUpdateTest()
        {
            IDigest digest1 = new ExtendedHashDigest();
            digest1.BlockUpdate(new byte[] { 1, 2, 3 });

            IDigest digest2 = new ExtendedHashDigest();
            digest2.BlockUpdate(new byte[] { 1, 2, 3, 4, 5 }, 0, 3);
            byte[] actualResult1 = new byte[256];
            byte[] actualResult2 = new byte[256];
            digest1.DoFinal(actualResult1);
            digest2.DoFinal(actualResult2);

            Assert.That(actualResult1, Is.EqualTo(actualResult2));
        }

        [Test]
        public void GetByteLengthTest()
        {
            IDigest digest = new ExtendedHashDigest();
            Assert.That(digest.GetByteLength(), Is.EqualTo(0));

            digest.BlockUpdate(new byte[] { 1, 2, 3 });
            Assert.That(digest.GetByteLength(), Is.EqualTo(3));

            digest.Update(4);
            Assert.That(digest.GetByteLength(), Is.EqualTo(4));

            digest.BlockUpdate(new byte[] { 5, 6, 7 }, 0, 2);
            Assert.That(digest.GetByteLength(), Is.EqualTo(6));

            digest.Reset();
            Assert.That(digest.GetByteLength(), Is.EqualTo(0));
        }

        [Test]
        public void GetDigestSizeTest()
        {
            IDigest digest = new ExtendedHashDigest();
            var actualResult = digest.GetDigestSize();
            Assert.That(actualResult, Is.EqualTo(256));

            byte[] array = new byte[1000];
            digest.BlockUpdate(array);
            Assert.That(actualResult, Is.EqualTo(256));
        }

        [Test]
        public void AlgorithmNameTest()
        {
            IDigest digest = new ExtendedHashDigest();
            var actualResult = digest.AlgorithmName;
            Assert.That(actualResult, Is.EqualTo("ExtendedHash"));
            digest.BlockUpdate(new byte[] { 1, 2, 3 });
            actualResult = digest.AlgorithmName;
            Assert.That(actualResult, Is.EqualTo("ExtendedHash"));
            digest.Update(4);
            actualResult = digest.AlgorithmName;
            Assert.That(actualResult, Is.EqualTo("ExtendedHash"));
            digest.BlockUpdate(new byte[] { 5, 6, 7 }, 0, 2);
            actualResult = digest.AlgorithmName;
            Assert.That(actualResult, Is.EqualTo("ExtendedHash"));
            digest.Reset();
            actualResult = digest.AlgorithmName;
            Assert.That(actualResult, Is.EqualTo("ExtendedHash"));
        }
    }
}
