using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SimpleEncDec
{
    class hmac
    {
        /// <summary>
        /// Generate a unique ApiKey that can later be associated with an ApiUser
        /// </summary>
        /// <returns></returns>
        public static string GenerateApiKey()
        {
            string randomKey = GenerateRandomKeyValue();
            string keyString = HashGeneratedString(randomKey);

            return keyString;
        }

        /// <summary>
        /// Generate a random symmetric key.
        /// </summary>
        /// <returns></returns>
        private static string GenerateRandomKeyValue()
        {
            var symAlg = SymmetricAlgorithm.Create("Rijndael");
            symAlg.KeySize = 128;
            byte[] key = symAlg.Key;
            var sb = new StringBuilder(key.Length * 2);
            foreach (byte b in key)
            {
                sb.AppendFormat("{0:x2}", b);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Hash the random string value that was created as to make it more random and return a 64 byte key.
        /// </summary>
        /// <param name="randomKey"></param>
        /// <returns></returns>
        private static string HashGeneratedString(string randomKey)
        {
            Guid g = Guid.NewGuid();
            string salt = Convert.ToBase64String(g.ToByteArray());
            salt = salt.Replace("=", "").Replace("+", "");

            byte[] saltBytes = Encoding.ASCII.GetBytes(salt);
            HashAlgorithm hashAlgorithm = new HMACSHA384(saltBytes);

            byte[] bytesToHash = Encoding.ASCII.GetBytes(randomKey);
            byte[] computedHashBytes = hashAlgorithm.ComputeHash(bytesToHash);

            string generatedKey = Convert.ToBase64String(computedHashBytes);
            return generatedKey;
        }
    }
}
