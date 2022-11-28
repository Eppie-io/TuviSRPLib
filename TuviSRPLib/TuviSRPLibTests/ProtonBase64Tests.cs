using ProtonBase64Lib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TuviSRPLibTests
{
    public class ProtonBase64Tests
    {
        [TestCase(new byte[] { 0, 1 })]
        [TestCase(new byte[] { 255, 255 })]
        [TestCase(new byte[] { 1, 1 })]
        [TestCase(new byte[] { 0, 0, 1 })]
        [TestCase(new byte[] { 255, 255, 255 })]
        [TestCase(new byte[] { 1, 1, 1 })]
        [TestCase(new byte[] { 128, 255, 1 })]
        [TestCase(new byte[] { 18, 231, 112 })]
        [TestCase(new byte[] { 0, 0, 0, 1 })]
        [TestCase(new byte[] { 255, 255, 255, 255 })]
        [TestCase(new byte[] { 1, 1, 1, 1 })]
        [TestCase(new byte[] { 138, 31, 192, 211, 234, 7, 77, 177, 54, 139 })]
        public void BytesToStringAndToBytes_CorrectConverting(byte[] array)
        {
            var actualResult = ProtonBase64.Decode(ProtonBase64.ToBase64String(array));
            Assert.AreEqual(array, actualResult);
        }

        [TestCase(new byte[] { 0, 0, 1 }, ".../")]
        [TestCase(new byte[] { 31, 32, 33 }, "Fw.f")]
        [TestCase(new byte[] { 233, 74, 89, 152, 12 }, "4SnXk.u")]
        [TestCase(new byte[] { 111, 29, 94, 201, 215, 75 }, "ZvzcwbbJ")]
        [TestCase(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 }, ".OGB/.SE/ueHAeqKBO2NC/CQCvOTDfaWEPmZF/ycFw.f")]
        public void BytesToBase64String_CorrectConverting(byte[] array, string expectedResult)
        {
            var actualResult = ProtonBase64.ToBase64String(array);
            Assert.AreEqual(expectedResult, actualResult);
        }
    }
}
