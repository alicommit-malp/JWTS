using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace JWTS.Test
{
    public class Tests
    {
        private const string Issuer = "issuer";
        private const string Audience = "audience";
        private const string OtpMasterKey = "Master_Key";
        private const int Validity = 60;


        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public async Task Test1()
        {
            //generating token  
            var claim = new Claim(ClaimTypes.Role, "admin");
            var token = global::JWTS.JWTS.Generate(
                Issuer,
                Audience,
                new List<Claim>() {claim},
                DateTime.UtcNow.AddSeconds(Validity),
                OtpMasterKey);


            //waiting and validating 
            var tokenOptions = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = Issuer,
                ValidAudience = Audience,
            };

            //the algorithm will guaranty token's validity before validation expires  
            var lastState = false;
            for (var i = 0; i < Validity; i++)
            {
                if(!Validate(token, tokenOptions)) Assert.Fail("Not valid before expiration!");
                else
                {
                    lastState = true;
                    Console.WriteLine($"{DateTime.Now} IS Valid");
                }
                await Task.Delay(1000);
            }
            
            //Due to TOTP algorithm working method after the expiration time of the token 
            // between 0 ~ 60 seconds the expiration of TOTP validity may be extended 
            await Task.Delay(60*1000);
            if(Validate(token,tokenOptions)) Assert.Fail("valid after expiration!");
            
            Assert.IsTrue(lastState); 
        }

        private static bool Validate(string token, TokenValidationParameters tokenOptions)
        {
            var result = global::JWTS.JWTS.Validate(token, tokenOptions, OtpMasterKey, Validity);
            return result != null && result.Claims.First(z => z.Type == ClaimTypes.Role).Value.Equals("admin");
        }
    }
}