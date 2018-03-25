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

            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };

            var content = "abcdefg";
            var contentBytes = Encoding.UTF8.GetBytes(content);

            var cipher = string.Empty;
            var cipherBytes = new byte[] { };

            Action __review = () =>
            {
                using (var aes = new AesManaged())
                {
                    // Encryption

                    var encryptor = aes.CreateEncryptor(key, iv);
                    using (var stream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(contentBytes, 0, contentBytes.Length);
                        }

                        cipherBytes = stream.ToArray();
                        cipher = Convert.ToBase64String(cipherBytes);

                    }

                    Console.WriteLine(string.Format("{0} => {1}", content, cipher));

                    // Decryption

                    cipherBytes = Convert.FromBase64String(cipher);

                    var decryptor = aes.CreateDecryptor(key, iv);
                    using (var stream = new MemoryStream(cipherBytes))
                    {
                        using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cryptoStream))
                            {
                                content = reader.ReadToEnd();
                            }
                        }
                    }

                    Console.WriteLine(string.Format("{0} => {1}", cipher, content));

                }
            };

            // __review();

            /// Use windows sdk to create self-signed cert
            ///     - makecert -r -sv test.pvk -n "CN=KTLiang" test.cert -a md5
            ///     - pvk2pfx -pvk test.pvk -spc test.cer -pfx test.pfx -po 123
            ///     - cer: public key file (no private key)
            ///     - pvk: private key file
            ///     - pfx: x509 complete format (public key + private key)

            var pvkFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pvk");
            var cerFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.cer");
            var pfxFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pfx");

            /// Experiment
            ///     - The cert has been applied MD5 as the hash algorithm
            ///     - Imitate the transmission of content

            var hashBytes = MD5.Create().ComputeHash(contentBytes);
            var hash = Convert.ToBase64String(hashBytes);

            Console.WriteLine("{0} => hash-to: {1}", content, hash);


            var certificate = new X509Certificate2(pfxFile, "123");
            












        }
    }
}
