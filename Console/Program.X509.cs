using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LearningSSL
{
    partial class Program
    {
        /// <summary>
        /// Note:
        ///     1. X509Cert includes: name, issuer, md5&sha and a public key
        ///     2. How they can be parsed and used in secure context
        /// </summary>
        static void X509ContentDemonstration()
        {
            /// Review how to perform a synmetric encryption:
            ///     - Use managed provider from System.Security namespace
            ///     - Use 32-bit length key
            ///     - Use 16-bit length vector to randomize cipher result (at 1st of block chain)

            var content = "abcdefg";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
            var cipher = string.Empty;

            using (var aes = new AesManaged())
            {
                // Encryption

                var contentBytes = Encoding.UTF8.GetBytes(content);
                var encryptor = aes.CreateEncryptor(key, iv);

                using (var stream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(contentBytes, 0, contentBytes.Length);
                    }

                    var cipherBytes = stream.ToArray();
                    cipher = Convert.ToBase64String(cipherBytes);

                }


                Console.WriteLine(string.Format("{0} => {1}", content, cipher));

                // Decryption

                var cipherBytes = Convert.FromBase64String(cipher);
                var decryptor = aes.CreateDecryptor(key, iv);





            }







        }
    }
}
