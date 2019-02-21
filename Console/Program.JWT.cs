using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;
using System.Net.Http;

namespace LearningSSL
{
    partial class Program
    {
        static void MinimumDependency()
        {
            // help to make crypto service ready (private key)
            var cert = new X509Certificate2(@"c:\test\notasecret.p12", "notasecret");
            var header = new { typ = "JWT", alg = "RS256" };

            // claimset
            var times = GetExpiryAndIssueDate();
            var claimset = new
            {
                iss = "firebase-adminsdk-eugj2@hummfcmdev-6b19f.iam.gserviceaccount.com",
                scope = "https://www.googleapis.com/auth/firebase.messaging",
                aud = "https://accounts.google.com/o/oauth2/token",
                iat = times[0],
                exp = times[1],
            };

            var serializer = new JavaScriptSerializer();

            // encoded header
            var headerSerialized = serializer.Serialize(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = Convert.ToBase64String(headerBytes);

            // encoded claimset
            var claimsetSerialized = serializer.Serialize(claimset);
            var claimsetBytes = Encoding.UTF8.GetBytes(claimsetSerialized);
            var claimsetEncoded = Convert.ToBase64String(claimsetBytes);

            // input
            var input = headerEncoded + "." + claimsetEncoded;
            var inputBytes = Encoding.UTF8.GetBytes(input);

            // signiture
            var rsa = cert.PrivateKey as RSACryptoServiceProvider;
            var cspParam = new CspParameters
            {
                KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName,
                KeyNumber = rsa.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2
            };

            var aescsp = new RSACryptoServiceProvider(cspParam) { PersistKeyInCsp = false };
            var signatureBytes = aescsp.SignData(inputBytes, "SHA256");
            var signatureEncoded = Convert.ToBase64String(signatureBytes);

            // jwt
            var jwt = headerEncoded + "." + claimsetEncoded + "." + signatureEncoded;

            var client = new HttpClient();
            var uri = new Uri("https://accounts.google.com/o/oauth2/token");

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "assertion", jwt },
                { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" }
            });

            var response = client.PostAsync(uri, content).Result;
            Console.WriteLine(response.Content.ReadAsStringAsync().Result);

        }

        private static int[] GetExpiryAndIssueDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var issueTime = DateTime.UtcNow;

            var iat = (int)issueTime.Subtract(utc0).TotalSeconds;
            var exp = iat + 3600;

            return new[] { iat, exp };
        }

    }
}
