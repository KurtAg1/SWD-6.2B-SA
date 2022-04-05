using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyNotes
{
    class Program
    {
        static void Main(string[] args)
        {
            string originalString = "Hello World!";

            // ENCODING
            Console.WriteLine("\n=== ENCODING ===");

            Encoding encodingUTF8 = Encoding.UTF8;
            byte[] stringAsBytes = encodingUTF8.GetBytes(originalString);
            string convertedString = System.Convert.ToBase64String(stringAsBytes);

            Console.WriteLine($"This is the originalString: {originalString}");
            Console.WriteLine($"This is the convertedString: {convertedString}");

            // HASHING
            Console.WriteLine("\n=== HASHING ===");
            HashAlgorithm sha512 = SHA512.Create();
            byte[] hashDigest = sha512.ComputeHash(stringAsBytes, 0, stringAsBytes.Length);
            string convertedHashDigest = System.Convert.ToBase64String(hashDigest);
            Console.WriteLine($"This is the HashDigest as a string: {convertedHashDigest}");

            /*
            using (FileStream fs = File.OpenRead("TextFile.txt"))
            {
                hashDigest = sha512.ComputeHash(fs);
            }
            */

            // SYMMETRIC ENCRYPTION
            Console.WriteLine("\n=== SYMMETRIC ENCRYPTION ===");
            Aes aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();

            string encryptedDataAsString = null;

            using(MemoryStream ms = new MemoryStream())
            {
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

            byte[] encryptedDataAsByte = System.Convert.FromBase64String(encryptedDataAsString);
            string plainTextData = null;

            using(MemoryStream ms = new MemoryStream(encryptedDataAsByte))
            {
                ms.Position = 0;

                using(CryptoStream cryptStream = new CryptoStream(
                    ms,
                    aes.CreateDecryptor(),
                    CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cryptStream))
                    {
                        plainTextData = sr.ReadToEnd();
                    }
                }
            }

            Console.WriteLine($"PlainText: {plainTextData}");

            // ASYMMETRIC ENCRYPTION
            Console.WriteLine("\n=== ASYMMETRIC ENCRYPTION ===");
            RSA rsa = RSA.Create();

            // public and private keys
            RSAParameters parameters = rsa.ExportParameters(true);

            // public keys only
            parameters = rsa.ExportParameters(false);

            // you can export and import the parameters
            string xmlParameters = rsa.ToXmlString(true);
            Console.WriteLine($"RSA Parameters: {xmlParameters}");
            rsa.FromXmlString(xmlParameters);

            byte[] rsaEncryptedString = rsa.Encrypt(stringAsBytes, RSAEncryptionPadding.Pkcs1);
            encryptedDataAsString = System.Convert.ToBase64String(rsaEncryptedString, 0, (int)rsaEncryptedString.Length);

            Console.WriteLine($"RSA Encrypted data as String: {encryptedDataAsString}");

            byte[] rsaDecryptedString = rsa.Decrypt(rsaEncryptedString, RSAEncryptionPadding.Pkcs1);
            plainTextData = encodingUTF8.GetString(rsaDecryptedString);

            Console.WriteLine($"RSA Decrypted plaintext: {plainTextData}");

            // DIGITAL SIGNATURE
            Console.WriteLine("\n=== DIGITAL SIGNATURE ===");
            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA512");
            byte[] signedHashValue = rsa.SignData(stringAsBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA512");

            if(rsaDeformatter.VerifySignature(hashDigest, signedHashValue))
            {
                Console.WriteLine("The signature is valid.");
            }
            else
            {
                Console.WriteLine("The signature is not valid.");
            }

            // PUBLIC KEY INFRASTRUCTURE
            // AND HYBRID ENCRYPTION
            Console.WriteLine("\n=== PUBLIC KEY INFRASTRUCTURE AND HYBRID ENCRYPTION ===");
            string secretMessage = "Hello World!";

            // RSA Crypto Service Provider on the remote computer
            RSACryptoServiceProvider yourRSACSP = new RSACryptoServiceProvider();
            // public key from remote computer
            byte[] yourPublicKey = yourRSACSP.ExportCspBlob(false);

            // RSA Crypto Service Provider on the local computer
            RSACryptoServiceProvider myRSACSP = new RSACryptoServiceProvider();
            // Load remote Public Key into local RSA Crypto Service Provider
            myRSACSP.ImportCspBlob(yourPublicKey);

            // The Key Exchange Formatter on the local computer
            RSAPKCS1KeyExchangeFormatter rsaKeyExchangeFormatter = new RSAPKCS1KeyExchangeFormatter(myRSACSP);

            // The Symmetric Encryption to pass the secret message
            Aes aesCSP = new AesCryptoServiceProvider();
            aesCSP.Padding = PaddingMode.PKCS7;

            byte[] encryptedSessionKey = rsaKeyExchangeFormatter.CreateKeyExchange(aesCSP.Key, typeof(Aes));
            byte[] encryptedMessage = null;
            byte[] _IV = aesCSP.IV;

            // encrypt the message locally
            using MemoryStream ciphertext = new MemoryStream();
            using CryptoStream myCryptoStream = new CryptoStream(ciphertext, aesCSP.CreateEncryptor(), CryptoStreamMode.Write);

            byte[] plainTextMessage = Encoding.UTF8.GetBytes(secretMessage);
            myCryptoStream.Write(plainTextMessage, 0, plainTextMessage.Length);
            myCryptoStream.Close();

            ciphertext.Flush();
            encryptedMessage = ciphertext.ToArray();

            // The Symmetric Encryption to receive the secret message on the remote computer
            using Aes yourAesCSP = new AesCryptoServiceProvider();

            yourAesCSP.IV = _IV;
            yourAesCSP.Padding = PaddingMode.PKCS7;

            // Decrypt the session key
            RSAPKCS1KeyExchangeDeformatter keyDeformatter = new RSAPKCS1KeyExchangeDeformatter(yourRSACSP);
            yourAesCSP.Key = keyDeformatter.DecryptKeyExchange(encryptedSessionKey);

            // Decrypt the message on the remote computer
            using MemoryStream plaintext = new MemoryStream();
            using CryptoStream yourCryptoStream = new CryptoStream(plaintext, yourAesCSP.CreateDecryptor(), CryptoStreamMode.Write);

            yourCryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
            yourCryptoStream.Close();

            string message = Encoding.UTF8.GetString(plaintext.ToArray());
            Console.WriteLine($"Key exchanged using RSA: {message}");

            Console.ReadKey();
        }
    }
}
