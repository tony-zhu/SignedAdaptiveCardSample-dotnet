// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Program.cs" company="Microsoft">
//   Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace SignedAdaptiveCardSample
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json;

    /// <summary>
    /// The sample program generaing Actionable Message email body with signed Adaptive Card
    /// </summary>
    class Program
    {
        /// <summary>
        /// Get the private key to sign the card
        /// </summary>
        /// <returns>RSA private key</returns>
        static SecurityKey GetSecurityKeyFromRSAPrivateKeyXml()
        {
            // This is the Outlook Actionable Message developer key, which is only valid in self-sending senario.
            // Production services should generate their own key pairs and register the public key with Actionable Message team.
            string rsaPrivateKeyXml = "<RSAKeyValue><Modulus>8WX2j9xybAUSllBoD1FA6prUpRdabvT/RQgU898tv75Sn0LSZz5fpm/5YJDdNqOVjxq611WPnfPgOaX6h/klmHhk57ZJBl7rNwlX2FgOYOhlA1Nzf22iwb8qCipTn/4ncllCTk hvVBm43SNToXLp1f9tXrZCgQORnw6BDDmKlLxfSFTtGi7afgj9x+dEHfVfg9J/7DlsARceR4Oyfs1nlG6fUqtp0ZcAOk5YxhfuSecAr+GnIP7Vv5zCquqT7zQ8hfyZ1K+8Lqz8xEvi2mnGKH1JT1dPpSbk8DQU5RYjG8ttaHorSGprxH1cunt5OIcvlEODYII2CF8+2OSE/iEhBQ==</Modulus><Exponent>AQAB</Ex ponent><P>+IYb0oc550Z+oZ062lQ2VX93lzXZhTE2Spg/kWI5JJM469XN7WiJpPzSGyR+mJxyuDMq/8b1rjkij5GkQ9isDY5GQIehKAfUrn2hsruondV8f31l54myoee6/dEJfkwowJFe15MdDSJzudfAfce8q 2Jf+sFkOXsu7mTdxbkNlyM=</P><Q>+Kj67aCnTWYv7z/HyKYoez6Ul2j8upcpyBMmhGj6hg8BIrW h7xnU19zUZWDg7BbarheN4zcNo5c2jS1IK9BqeB7HVkrfOcW5optgBrZ8+GKBOWX6pAbt5c8Tqeb +LCDOeqzkJ2XmNt8UrWnloL/ZO7LCFQP+DcZG/VyeyXvKfbc=</Q><DP>SuP23GE9lLEMld0QkBxSZz9LJXjnvJhQ2Pe6KDBmMdxficnbDVC0MdCx69X6hDiY5WMd8Qfenwq+nG7yBjPz3P3js6xrZum9MHvRT0/3huB/bNe37qby+pEfKz9j0fhXS3hDEUlWts+L+hPHAOBAvZCehazja+LwCIzCu8OBEes=</DP><DQ>XhK/7AqtgNC6Lc95a+XAxu+kE6w6gPUTb4gfOFTnArTGfzUsMGMbbRc0m64NKgRzcw2iNmXrmQpqLvsEpN7SiONMEs98qESvuF8D80Yy/V12+hokus2MTzcKf2rOmi9HLo4eOvGIKRY4omq /3xL1wmoclwrNoLR0wwG5aQyWTP0=</DQ><InverseQ>A06rQ8aGgMnt3kysCGETrffhmlc6fVKA a7f8NX8Chi79uK0RjGU1xPkTAZ47X1ytlPJNeUhgPf5M65kAyV1o3Dxh3ZCi6Qysa+cA8HYFKEPMTk ImOpg2ps7Amn5Si+UNW+DL6xse86mh/53gCDggVeGYOBkdOe4BPs+m0GjEvOg=</InverseQ><D>g7Xsd8YCMGn8IEOy41ikIN1l1MYPM6c9eL7WH9HPtmTz062z+10O91L1L/kametbeP9Onpsyhy4/U3T6YyJPnwdhlwPgiDdWA2t3oLU68ykZpFzuEcMSIMBbAbzib9NOVpfZE7l19N8r/Ix/3wFCEN8TH7A2TQpTdAOH6dGjiU7HL8K652HybW33K5qfSTmmoMZ6Kc1InZFSJlYJ3/ysGUMRE4OssGLXW+94kKeOBPu+QB+kFKpC7FNuvnql9BPWZjrS22hW2dLQO991BEzgE0qm1CGKDuDZEK4EiabxtgJVdK8x4AkaqsbZAJr4pr6fna3009jygVlhWs4AT1kp6Q==</D></RSAKeyValue>";

            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaPrivateKeyXml);

            return new RsaSecurityKey(rsa);
        }

        /// <summary>
        /// Generate the Actionable Message email body with signed Adaptive Card
        /// </summary>
        /// <param name="args">Command line args</param>
        static void Main(string[] args)
        {
            SecurityKey securityKey = GetSecurityKeyFromRSAPrivateKeyXml();
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.SetDefaultTimesOnTokenCreation = false;

            string adaptiveCardRawJson = File.ReadAllText("card.json");
            string minifiedCard = JsonConvert.SerializeObject(JsonConvert.DeserializeObject(adaptiveCardRawJson));

            // The Actionable Message provider ID generated during provider registration
            string originator = "65c680ef-36a6-4a1b-b84c-a7b5c6198792";

            // Recipients of the email
            string[] recipients = { "john@contoso.com", "jane@contoso.com" };

            // Sender of the email
            string sender = "service-account@contoso.com";

            ClaimsIdentity  subject = new ClaimsIdentity(
                new Claim[]
                {
                    new Claim("sender", sender),
                    new Claim("originator", originator),
                    new Claim("recipientsSerialized", JsonConvert.SerializeObject(recipients)),
                    new Claim("adaptiveCardSerialized", minifiedCard)
                });

            JwtSecurityToken token = handler.CreateJwtSecurityToken(subject: subject, issuedAt:DateTime.UtcNow, signingCredentials: signingCredentials);

            string emailBody = File.ReadAllText("signed_adaptive_template.html");

            emailBody = emailBody.Replace("{{signedCardPayload}}", token.RawData);

            Console.WriteLine(emailBody);
            Console.Read();
        }
    }
}
