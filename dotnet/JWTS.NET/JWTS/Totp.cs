using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JWTS
{
    /// <summary>
    /// TOTP class provide functionality
    ///    -generate time-based one time password
    ///    -generate time-based one time password for range of dates 
    /// </summary>
    public class Totp
    {
        private readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Will generate a 6 digit TOTP code which will be valid for maximum 30 seconds 
        /// </summary>
        /// <param name="otpKey">Master Key required for the TOTP</param>
        /// <returns>6 digits TOTP code </returns>
        public int Generate(string otpKey)
        {
            return TotpHash(otpKey, GetCurrentCounter());
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="otpKey"></param>
        /// <param name="timeTolerance"></param>
        /// <returns></returns>
        public IEnumerable<int> GetValidCodes(
            string otpKey,
            TimeSpan timeTolerance)
        {
            var intList = new List<int>();
            var currentCounter = GetCurrentCounter();
            var num1 = 0;
            if (timeTolerance.TotalSeconds > 30.0)
                num1 = Convert.ToInt32(timeTolerance.TotalSeconds / 30.0);
            var num2 = currentCounter - num1;
            var num3 = currentCounter + num1;
            for (var counter = num2; counter <= num3; ++counter)
                intList.Add(Generate(otpKey, counter));
            return intList.ToArray();
        }

        private static int Generate(string otpKey, long counter, int digits = 6)
        {
            return TotpHash(otpKey, counter, digits);
        }

        private long GetCurrentCounter()
        {
            return (long) (DateTime.UtcNow - _unixEpoch).TotalSeconds / 30L;
        }


        private static int TotpHash(string secret, long iterationNumber, int digits = 6)
        {
            return TotpHash(Encoding.UTF8.GetBytes(secret), iterationNumber, digits);
        }

        private static int TotpHash(byte[] key, long iterationNumber, int digits = 6)
        {
            var bytes = BitConverter.GetBytes(iterationNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse((Array) bytes);
            var hash = new HMACSHA1(key).ComputeHash(bytes);
            var index = hash[hash.Length - 1] & 15;
            return ((hash[index] & sbyte.MaxValue) << 24 | hash[index + 1] << 16 |
                    hash[index + 2] << 8 | hash[index + 3]) % (int) Math.Pow(10.0, digits);
        }
    }
}