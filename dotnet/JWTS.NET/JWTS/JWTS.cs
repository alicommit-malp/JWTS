using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JWTS
{
    /// <summary>
    /// Json Web Token Secure
    /// </summary>
    public class JWTS
    {
        /// <summary>
        /// Generate a JWT token with provided params 
        /// </summary>
        /// <param name="issuer">Issuer of the token</param>
        /// <param name="audience">audience of the token</param>
        /// <param name="claims">List of the claims related to the user of this token</param>
        /// <param name="expire">The date & time which the token should be expired in UTC timezone</param>
        /// <param name="otpKey">the master key of the TOTP</param>
        /// <returns>the JWT</returns>
        public static string Generate(string issuer, string audience, IEnumerable<Claim> claims, DateTime? expire,
            string otpKey)
        {
            //to satisfy the the length of the jwt secret   
            var jwtKey = $"{otpKey}{Convert.ToString(new Totp().Generate(otpKey))}";
            var secretKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokeOptions = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expire,
                signingCredentials: signinCredentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
            return tokenString;
        }

        /// <summary>
        /// Validate the token with TOTP
        /// </summary>
        /// <param name="token">JWT token to be validated</param>
        /// <param name="parameters">Token validation parameters</param>
        /// <param name="otpKey">the master key of TOTP</param>
        /// <param name="validationDurationSeconds">The validation duration in seconds</param>
        /// <returns>Claim_principle object or null</returns>
        public static ClaimsPrincipal Validate(string token, TokenValidationParameters parameters, string otpKey,
            long validationDurationSeconds)
        {
            var validCodes = new Totp().GetValidCodes(otpKey,
                DateTime.UtcNow.AddSeconds(31) - DateTime.UtcNow.AddSeconds(-validationDurationSeconds));
            foreach (var key in validCodes)
            {
                try
                {
                    return Validate(token, parameters, $"{otpKey}{Convert.ToString(key)}");
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            return null;
        }

        private static ClaimsPrincipal Validate(string token, TokenValidationParameters parameters, string key)
        {
            parameters.IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var validator = new JwtSecurityTokenHandler();
            return validator.ValidateToken(token, parameters, out _);
        }
    }
}