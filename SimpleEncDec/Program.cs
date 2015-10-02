using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleEncDec
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("/* Rijndael Test*/");
            string plainText = "Hello, World!";    // original plaintext

            string passPhrase = "Pas5pr@se";        // can be any string
            string saltValue = "s@1tValue";        // can be any string
            string hashAlgorithm = "SHA1";             // can be "MD5"
            int passwordIterations = 2;                // can be any number
            string initVector = "@1B2c3D4e5F6g7H8"; // must be 16 bytes
            int keySize = 256;                // can be 192 or 128

            Console.WriteLine(String.Format("Plaintext : {0}", plainText));

            string cipherText = RijndaelSimple.Encrypt
            (
                plainText,
                passPhrase,
                saltValue,
                hashAlgorithm,
                passwordIterations,
                initVector,
                keySize
            );

            Console.WriteLine(String.Format("Encrypted : {0}", cipherText));

            plainText = RijndaelSimple.Decrypt
            (
                cipherText,
                passPhrase,
                saltValue,
                hashAlgorithm,
                passwordIterations,
                initVector,
                keySize
            );

            Console.WriteLine(String.Format("Decrypted : {0}", plainText));
            
            Console.WriteLine("\n\n/* Rijndael Enhanced Test*/");
            string eplainText = "Hello, World!";    // original plaintext
            string ecipherText = "";                 // encrypted text
            string epassPhrase = "Pas5pr@se";        // can be any string
            string einitVector = "@1B2c3D4e5F6g7H8"; // must be 16 bytes

            // Before encrypting data, we will append plain text to a random
            // salt value, which will be between 4 and 8 bytes long (implicitly
            // used defaults).
            RijndaelEnhanced rijndaelKey =
                new RijndaelEnhanced(epassPhrase, einitVector);

            Console.WriteLine(String.Format("Plaintext   : {0}\n", eplainText));

            // Encrypt the same plain text data 10 time (using the same key,
            // initialization vector, etc) and see the resulting cipher text;
            // encrypted values will be different.
            for (int i = 0; i < 10; i++)
            {
                ecipherText = rijndaelKey.Encrypt(eplainText);
                Console.WriteLine(
                    String.Format("Encrypted #{0}: {1}", i, ecipherText));
                eplainText = rijndaelKey.Decrypt(ecipherText);
            }

            // Make sure we got decryption working correctly.
            Console.WriteLine(String.Format("\nDecrypted   : {0}", eplainText));


            Console.WriteLine("\n\n/* Hmac & Crypto*/");


            string key = Cryptography.Encrypt(hmac.GenerateApiKey());
            Console.WriteLine(key);
            Console.ReadKey();
        }
    }


}
