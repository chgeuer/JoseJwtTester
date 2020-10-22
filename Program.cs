namespace JoseJwtTester
{
    using System;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Jose; // <PackageReference Include="jose-jwt" Version="2.6.0" />

    public class ApplicationCreationRequest
    {
        [JsonPropertyName("tenantId")]
        public string TenantId { get; set; }

        [JsonPropertyName("subscriptionId")]
        public Guid SubscriptionId { get; set; }

        [JsonPropertyName("timeStamp")]
        public DateTimeOffset TimeStamp { get; set; }

        public override string ToString() => $"{nameof(ApplicationCreationRequest)} {this.TenantId} {this.SubscriptionId} {this.TimeStamp}";
    }

    public enum SignatureValidity { Invalid = 0, Valid = 1 }

    class Program
    {
        public static string SignRequest<T>(string signingKey, T request)
        {
            var secretKey = Convert.FromBase64String(signingKey);

            var payloadString = JsonSerializer.Serialize(request);
            return JWT.Encode(payloadString, secretKey, JwsAlgorithm.HS256);
        }

        public static (SignatureValidity, T) ValidateRequest<T>(string verificationKey, string token)
        {
            var secretKey = Convert.FromBase64String(verificationKey);

            try
            {
                var json = JWT.Decode(token, secretKey);
                Console.WriteLine(json);

                var req = JsonSerializer.Deserialize<T>(json);
                return (SignatureValidity.Valid, req);
            }
            catch (IntegrityException)
            {
                return (SignatureValidity.Invalid, default(T));
            }
        }
        
        //public static byte[] StringToByteArray(string hex)
        //{
        //    return Enumerable.Range(0, hex.Length)
        //                     .Where(x => x % 2 == 0)
        //                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
        //                     .ToArray();
        //}

        //public static string ByteArrayToString(byte[] ba)
        //{
        //    return BitConverter.ToString(ba).Replace("-", "");
        //}

        //public static string hmac_sha256(string base64Key, string plaintext)
        //{
        //    var hmac = HMAC.Create("HMACSHA256");
        //    hmac.Key = Convert.FromBase64String(base64Key);
        //    var hashed = hmac.ComputeHash(Encoding.UTF8.GetBytes(plaintext));
        //    return Convert.ToBase64String(hashed);
        //}

        static void Main(string[] args)
        {
            var signingKey = "pDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo=";

            var request = new ApplicationCreationRequest
            {
                SubscriptionId = Guid.Parse("fb7fdc26-b0e5-45b6-8119-7bc48bc12e4e"),
                TenantId = "chgeuerfte.onmicrosoft.com",
                // TimeStamp = DateTimeOffset.UtcNow,
                TimeStamp = new DateTimeOffset(new DateTime(2020, 10, 21, 11, 36, 01, DateTimeKind.Utc)) // "2020-10-21T11:36:01Z"
            };

            string token = SignRequest(signingKey, request);

            Console.Out.Write("Enter token: "); token = Console.ReadLine().Trim();

            Console.WriteLine($".NET token: {token}");

            bool noTampering = true;
            var validationKey = noTampering ? signingKey : "aDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo=";

            switch (ValidateRequest<ApplicationCreationRequest>(validationKey, token))
            {
                case (SignatureValidity.Valid, var r): 
                    Console.WriteLine(r);
                    break;
                case (SignatureValidity.Invalid, _):
                    Console.Error.WriteLine("Invalid request");
                    break;
            }
        }

        #region A bit too much lambda

        public static Func<T, string> RequestSigner<T>(string signingKey)
        {
            var secretKey = Convert.FromBase64String(signingKey);

            return (T request) =>
            {
                var payloadString = JsonSerializer.Serialize(request);
                return JWT.Encode(payloadString, secretKey, JwsAlgorithm.HS256);
            };
        }

        public static Func<string, (SignatureValidity, T)> RequestVerifier<T>(string verificationKey)
        {
            var secretKey = Convert.FromBase64String(verificationKey);

            return (string token) =>
            {
                try
                {
                    var json = JWT.Decode(token, secretKey);
                    var req = JsonSerializer.Deserialize<T>(json);
                    return (SignatureValidity.Valid, req);
                }
                catch (IntegrityException)
                {
                    return (SignatureValidity.Invalid, default(T));
                }
            };
        }

        static void FunctionalOverload()
        {
            var signingKey = "pDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo=";

            var request = new ApplicationCreationRequest
            {
                SubscriptionId = Guid.Parse("fb7fdc26-b0e5-45b6-8119-7bc48bc12e4e"),
                TenantId = "chgeuerfte.onmicrosoft.com",
                TimeStamp = DateTimeOffset.UtcNow
            };

            string token = RequestSigner<ApplicationCreationRequest>(signingKey)(request);
            Console.WriteLine(token);
            bool noTampering = true;
            var validationKey = noTampering ? signingKey : "aDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo=";

            switch (RequestVerifier<ApplicationCreationRequest>(validationKey)(token))
            {
                case (SignatureValidity.Valid, var r):
                    Console.WriteLine(r);
                    break;
                case (SignatureValidity.Invalid, _):
                    Console.Error.WriteLine("Invalid request");
                    break;
            }
        }

        #endregion
    }
}
