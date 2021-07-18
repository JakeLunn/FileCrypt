using Kurukuru;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace FileCrypt
{
    class Program
    {
        /// <param name="keyOut">The file path for exporting a private key (used only by the create-key command)/</param>
        /// <param name="keyIn">The file path to the private key that is used for cryptographic commands (used by: encrypt, decrypt)</param>
        /// <param name="fileIn">The file path to the input file (used by: encrypt, decrypt)</param>
        /// <param name="fileOut">The file path to the output file to be created by a command (used only by the decrypt command)</param>
        /// <param name="args">Commands: create-key, encrypt, decrypt</param>
        static void Main(string keyOut = null,
            string keyIn = null,
            string fileIn = null,
            string fileOut = null,
            string[] args = null)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("A command was not specified. Please try: create-key, encrypt, decrypt, or --help");
                return;
            }

            var command = args[0];

            try
            {
                switch (command.ToLowerInvariant())
                {
                    case "create-key":
                        ValidateParams(new Dictionary<string, object> { [nameof(keyOut)] = keyOut });
                        CreateRsaKey(keyOut);
                        break;
                    case "encrypt":
                        ValidateParams(new Dictionary<string, object>
                        {
                            [nameof(keyIn)] = keyIn,
                            [nameof(fileIn)] = fileIn
                        });
                        EncryptFile(ImportRsaKey(keyIn), fileIn, fileOut);
                        break;
                    case "decrypt":
                        ValidateParams(new Dictionary<string, object>
                        {
                            [nameof(keyIn)] = keyIn,
                            [nameof(fileIn)] = fileIn,
                            [nameof(fileOut)] = fileOut
                        });
                        DecryptFile(ImportRsaKey(keyIn), fileIn, fileOut);
                        break;
                }
            }
            catch (Exception e)
            {
                if (e is ArgumentException || e is FileNotFoundException)
                {
                    Console.WriteLine(e.Message);
                    return;
                }

                throw;
            }
        }

        static void ValidateParams(Dictionary<string, object> namedParameters)
        {
            foreach (var namedParameter in namedParameters)
            {
                if (namedParameter.Value == null)
                    throw new ArgumentException($"Parameter '{namedParameter.Key}' is null");
                if (namedParameter.Value is string && string.IsNullOrWhiteSpace(namedParameter.Value as string))
                    throw new ArgumentException($"Parameter '{namedParameter.Key}' has a null or empty value.");
            }
        }

        #region Encryption/Decryption
        static void EncryptFile(RSA rsa, string fileIn, string fileOut = null)
        {
            var aes = Aes.Create();
            var transform = aes.CreateEncryptor();

            var encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);

            var lKey = encryptedKey.Length;
            var lenK = BitConverter.GetBytes(lKey);

            var lIV = aes.IV.Length;
            var lenIV = BitConverter.GetBytes(lIV);

            if (fileOut == null)
            {
                var fileExt = fileIn.Substring(fileIn.LastIndexOf("."), fileIn.Length - fileIn.LastIndexOf("."));
                fileOut = fileIn.Replace(fileExt, ".enc");
            }

            if (!fileOut.EndsWith(".enc"))
            {
                throw new ArgumentException("Output file must have the '.enc' file extension");
            }

            Spinner.Start("Encrypting...", spinner =>
            {
                using (var outFs = new FileStream(fileOut, FileMode.Create))
                {
                    outFs.Write(lenK, 0, 4);
                    outFs.Write(lenIV, 0, 4);
                    outFs.Write(encryptedKey, 0, lKey);
                    outFs.Write(aes.IV, 0, lIV);

                    using (CryptoStream outStream = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        int count = 0;
                        int offset = 0;

                        var blockSizeBytes = aes.BlockSize / 8;
                        var data = new byte[blockSizeBytes];
                        var bytesRead = 0;

                        using (FileStream inFs = new FileStream(fileIn, FileMode.Open))
                        {
                            do
                            {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                offset += count;
                                outStream.Write(data, 0, count);
                                bytesRead += blockSizeBytes;
                            } while (count > 0);

                            inFs.Close();
                        }

                        outStream.FlushFinalBlock();
                        outStream.Close();
                    }

                    outFs.Close();
                }
            });

            Console.WriteLine($"File was encrypted and saved to '{fileOut}'");
        }

        static void DecryptFile(RSA rsa, string fileIn, string fileOut)
        {
            if (!fileIn.EndsWith(".enc"))
                throw new ArgumentException($"Invalid parameter {nameof(fileIn)}. File extension should be '.enc'");

            var aes = Aes.Create();

            var lenK = new byte[4];
            var lenIV = new byte[4];

            Spinner.Start("Decrypting...", spinner =>
            {
                using (var inFs = new FileStream(fileIn, FileMode.Open))
                {
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(lenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(lenIV, 0, 3);

                    var lK = BitConverter.ToInt32(lenK, 0);
                    var lIV = BitConverter.ToInt32(lenIV, 0);

                    var startC = lK + lIV + 8;
                    var lC = (int)inFs.Length - startC;

                    var encryptedKey = new byte[lK];
                    var iv = new byte[lIV];

                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(encryptedKey, 0, lK);
                    inFs.Seek(8 + lK, SeekOrigin.Begin);
                    inFs.Read(iv, 0, lIV);

                    Directory.CreateDirectory(fileOut.Substring(0, fileOut.LastIndexOf("\\")));

                    var decryptedKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);

                    var transform = aes.CreateDecryptor(decryptedKey, iv);

                    using (var outFs = new FileStream(fileOut, FileMode.Create))
                    {
                        var count = 0;
                        var offset = 0;

                        var blockSizeBytes = aes.BlockSize / 8;
                        var data = new byte[blockSizeBytes];

                        inFs.Seek(startC, SeekOrigin.Begin);
                        using (CryptoStream outStream = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {
                            do
                            {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                offset += count;
                                outStream.Write(data, 0, count);
                            } while (count > 0);

                            outStream.FlushFinalBlock();
                            outStream.Close();
                        }

                        outFs.Close();
                    }
                    inFs.Close();
                }
            });

            Console.WriteLine($"File was decrypted and saved to '{fileOut}'");
        }
        #endregion Encryption/Decryption

        #region Keys
        static RSA ImportRsaKey(string keyIn)
        {
            if (!keyIn.EndsWith(".pem"))
                throw new ArgumentException($"Invalid {nameof(keyIn)} specified. Import file must end with the '.pem' extension.");

            var rsa = RSA.Create(4096);
            var pemFile = new FileInfo(keyIn);

            if (!pemFile.Exists)
                throw new FileNotFoundException($"File at {keyIn} does not exist!");

            var text = File.ReadAllText(pemFile.FullName);

            if (!Regex.IsMatch(text, @"\n(.+?)\n"))
                throw new ApplicationException($"File at {keyIn} was in an invalid format.");

            var match = Regex.Match(text, @"\n(.+?)\n");
            var pvk = Convert.FromBase64String(match.Groups[1].Value);

            rsa.ImportRSAPrivateKey(pvk, out _);
            return rsa;
        }

        static void CreateRsaKey(string keyOut)
        {
            if (!keyOut.EndsWith(".pem"))
                throw new ArgumentException($"Invalid {nameof(keyOut)} specified. Export file must end with the '.pem' extension.");

            var rsa = RSA.Create(4096);

            const string header = "-----BEGIN RSA PRIVATE KEY-----";
            const string footer = "-----END RSA PRIVATE KEY-----";

            string pvk = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            string pem = $"{header}\n{pvk}\n{footer}";

            var pemFile = new FileInfo(keyOut);
            Directory.CreateDirectory(pemFile.DirectoryName);

            File.WriteAllText(pemFile.FullName, pem);
            Console.WriteLine($"Private key has been exported to: {pemFile.FullName}");
        }
        #endregion Keys
    }
}
