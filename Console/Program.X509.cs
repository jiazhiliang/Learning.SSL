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

            __review();

            /// Use windows sdk to create self-signed cert
            ///     - makecert -r -sv test.pvk -n "CN=KTLiang" test.cer
            ///     - pvk2pfx -pvk test.pvk -spc test.cer -pfx test.pfx -po 123
            ///     - cer: public key file (no private key)
            ///     - pvk: private key file
            ///     - pfx: x509 complete format (public key + private key)

            var pvkFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pvk");
            var cerFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.cer");
            var pfxFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pfx");

            /// Recipient
            ///     - Cert file has been sent from server and received by client
            ///     - Only public key info is included in the cert

            var clientReceivedCert = new X509Certificate2(cerFile, "123");
            var cerRSA = clientReceivedCert.GetRSAPublicKey();

            /// Client accepts the cert and raise a challenge to server 
            ///     - Use public key to encrypt a text
            ///     - If server is the holder of private key, it should be able to decrypt and show back the content

            content = "hello, server.";
            contentBytes = Encoding.UTF8.GetBytes(content);

            cipherBytes = cerRSA.Encrypt(contentBytes, RSAEncryptionPadding.OaepSHA1);
            cipher = Convert.ToBase64String(cipherBytes);

            Console.WriteLine("Challenge: {0} with lengh {1}", cipher, cipherBytes.Length);

            var serverCert = new X509Certificate2(pfxFile, "123");
            var pvkRSA = serverCert.GetRSAPrivateKey();

            contentBytes = pvkRSA.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA1);
            content = Encoding.UTF8.GetString(contentBytes);

            Console.WriteLine(string.Format("Challenge accepted, you just said \"{0}\" (I'm the key owner)", content));

            /// Client will nominate an asyn key from now on
            ///     - Using the same mechanism

            contentBytes = new byte[key.Length + iv.Length];
            key.CopyTo(contentBytes, 0);
            iv.CopyTo(contentBytes, key.Length);
            content = Convert.ToBase64String(contentBytes);

            cipherBytes = cerRSA.Encrypt(contentBytes, RSAEncryptionPadding.OaepSHA1);
            cipher = Convert.ToBase64String(cipherBytes);

            Console.WriteLine("key planned: {0}", content);

            contentBytes = pvkRSA.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA1);
            content = Convert.ToBase64String(contentBytes);

            var serverKey = new byte[key.Length];
            var serverIV = new byte[iv.Length];

            Array.Copy(contentBytes, serverKey, 32);
            Array.Copy(contentBytes, 32, serverIV, 0, 16);

            Console.WriteLine("key confirm: {0}", content);

            /// Now going to send the detail information text between client and server
            /// 

            content = "client said: it's a sceret conversation.";
            contentBytes = Encoding.UTF8.GetBytes(content);

            /// Instead of using encoding, contentBytes should be the cipherBytes 
            ///     created by AesManaged. Becase now key and iv are both known to each parties

            var hashBytes = SHA1.Create().ComputeHash(contentBytes);
            var serverSignature = pvkRSA.SignHash(hashBytes, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            /// Client will:
            ///     - Received contentBytes and compute the hash the same way

            var clientComputedHashBytes = SHA1.Create().ComputeHash(contentBytes);
            var authenticated = pvkRSA.VerifyHash(clientComputedHashBytes, serverSignature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            Console.WriteLine(string.Format("Authentication of this content: {0}", authenticated));

            /// This marks the end of imitation of SSL under the dispatch of X509-standard PPK info
            ///     - Only private key owner can sigh and declare the content's Confidentiality, Integrity and Availability
            ///     - Public key can continuously used to verify the signature from private key owner
            ///     - If both part must be involved in authentication, exchange of both certs is needed

        }
    }
}
