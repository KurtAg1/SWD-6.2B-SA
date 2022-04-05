using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    class Program
    {

        static void Example1()
        {
            string plainText = "Hello World!";

            Encoding encodingUTF8 = Encoding.UTF8;
            byte[] utf8encodedText = encodingUTF8.GetBytes(plainText);
            string decodedString = encodingUTF8.GetString(utf8encodedText);

            string utf8encodedTextAsString = Convert.ToBase64String(utf8encodedText);
            byte[] convertedBackToByte = Convert.FromBase64String(utf8encodedTextAsString);

            Console.WriteLine($"The original plain text: {plainText}");
            Console.WriteLine($"The utf8 encoded plaintext (converted to a string): {utf8encodedTextAsString}");

            byte[] encodedTextFromFile = null;
            using (FileStream fs = File.OpenRead("TextFile.txt"))
            {
                // example with nested streams
                using (StreamReader sr = new StreamReader(fs))
                {
                    // read everything as a string
                    string stringFromFile = sr.ReadToEnd();
                }

                fs.Position = 0;

                // assume that the fileLength is within integer size
                // some files may be longer
                int fileLength = (int)fs.Length;
                encodedTextFromFile = new byte[fileLength];

                // read can only accept integer lengths
                // if the file is longer, we need some alternative...
                fs.Read(encodedTextFromFile, 0, fileLength);

                fs.Flush();

            }
        }

        static void Exercise1()
        {
            string originalString = "Hello World!";
            Encoding encodingUTF8 = Encoding.UTF8;
            byte[] stringAsBytes = encodingUTF8.GetBytes(originalString);
            string convertedString = System.Convert.ToBase64String(stringAsBytes);
            Console.WriteLine($"This is the originalString: {originalString}");
            Console.WriteLine($"This is the convertedString: {convertedString}");

            HashAlgorithm sha512 = SHA512.Create();
            byte[] hashDigest = sha512.ComputeHash(stringAsBytes, 0, stringAsBytes.Length);
            string convertedHashDigest = System.Convert.ToBase64String(hashDigest);
            Console.WriteLine($"This is the HashDigest as a string: {convertedHashDigest}");

            Aes aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();

            string encryptedDataAsString = null;

            using (MemoryStream ms = new MemoryStream()){
                using (CryptoStream cs = new CryptoStream(
                    ms,
                    aes.CreateEncryptor(),
                    CryptoStreamMode.Write))
                {
                    cs.Write(stringAsBytes, 0, stringAsBytes.Length);
                    cs.FlushFinalBlock();

                    ms.Position = 0;
                    byte[] buffer = ms.GetBuffer();
                    encryptedDataAsString = System.Convert.ToBase64String(buffer, 0, (int)ms.Length);
                }
            }

            Console.WriteLine($"Encrypted data as String: {encryptedDataAsString}");

            byte[] encrypedDataAsByte = System.Convert.FromBase64String(encryptedDataAsString);
            string plainTextData = null;

            using (MemoryStream ms = new MemoryStream(encrypedDataAsByte))
            {
                ms.Position = 0;

                using (CryptoStream cryptoStream = new CryptoStream(
                    ms, aes.CreateDecryptor(),
                    CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cryptoStream))
                    {
                        plainTextData = sr.ReadToEnd();
                    }
                }
            }

            Console.WriteLine($"PlainText: {plainTextData}");

        }

        static void Main(string[] args)
        {
            Exercise1();
        }
    }
}
