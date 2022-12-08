using Org.BouncyCastle.Utilities.Encoders;
using TuviSRPLib.Utils;

namespace TuviSRPLibTests
{
    public class BCBigIntExtensionTests
    {
        [TestCase(new byte[] { 255 }, new byte[] { 255 })]
        [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 3, 2, 1 })]
        [TestCase(new byte[] { 12, 34, 56, 78, 90 }, new byte[] { 90, 78, 56, 34, 12 })]
        public void ToLowEndian_CorrectConverting(byte[] initialArray, byte[] expectedArray)
        {
            BigInteger number = new BigInteger(1, initialArray);
            var actualResult = number.ToLowEndianByteArray();
            Assert.That(actualResult, Is.EqualTo(expectedArray));
        }

        [TestCase(new byte[] { 1, 2, 3, 4, 5 }, 5, new byte[] { 5, 4, 3, 2, 1, })]
        [TestCase(new byte[] { 1, 2, 3 }, 7, new byte[] { 3, 2, 1, 0, 0, 0, 0 })]
        [TestCase(new byte[] { 2 }, 10, new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0 })]
        [TestCase(new byte[] { 11, 22, 33, 44, 55 }, 3, new byte[] { 55, 44, 33 })]
        public void ToLowEndianNBytes_CorrectConverting(byte[] initialArray, int N, byte[] expectedArray)
        {
            BigInteger number = new BigInteger(1, initialArray);
            var actualResult = number.ToLowEndianNByteArray(N);
            Assert.That(actualResult, Is.EqualTo(expectedArray));
        }

        [TestCase(new byte[] { 2 }, new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })]
        [TestCase(new byte[] { 2, 15, 76 }, new byte[] { 76, 15, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })]
        public void ToLowEndianNBytesWithoutParam_CorrectConverting(byte[] initialArray, byte[] expectedArray)
        {
            BigInteger number = new BigInteger(1, initialArray);
            var actualResult = number.ToLowEndianNByteArray();
            Assert.That(actualResult, Is.EqualTo(expectedArray));
        }

        [TestCase("yKlc5/CvObfoiw==")]
        [TestCase("W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==")]
        [TestCase("Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==")]
        public void ToBase64_CorrectConverting(string base64Number)
        {
            var decodedBase64Number = Base64.Decode(base64Number);
            BigInteger number = new BigInteger(1, decodedBase64Number.Reverse().ToArray());
            var actualResult = number.ToBase64();
            Assert.That(actualResult, Is.EqualTo(base64Number));
        }
    }
}
