using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace _17743_Mihajlo_Marjanovic_ZI_Projekat
{
    class Program
    {
        static void compareTwoFilesWithSHA256(string path1, string path2)
        {
            Console.WriteLine("Poredimo fajlove: " + path1 + " i " + path2 + " pomocu SHA-256 hash funkcije:");

            string hash1 = StringHashOfTheFile(path1);
            string hash2 = StringHashOfTheFile(path2);

            Console.WriteLine("Hash 1. fajla: " + hash1);
            Console.WriteLine("Hash 2. fajla: " + hash2);

            if (hash1 == hash2)
            {
                Console.WriteLine("Fajlovi su isti");
            }
            else
            {
                Console.WriteLine("Fajlovi su razliciti");
            }
        }
        static string StringHashOfTheFile(string fileName)
        {
            // read all bytes from file
            byte[] fileBytes = File.ReadAllBytes(fileName);

            // compute hash
            byte[] hash = SHA256.ComputeHash(fileBytes);

            //return Convert.ToBase64String(hash);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
        static void a5_1()
        {
            Console.WriteLine("------ A5/1 ------");
            int[] a5_1_key = { 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1,
                1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
                1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0,
                0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0 };

            int[] a5_1_text = { 1, 0, 0, 1, 0 };

            A5_1 a5_1 = new A5_1(a5_1_key);
            int[] a5_1_cipher = a5_1.Crypt(a5_1_text);
            int[] a5_1_decrypted = a5_1.Decrypt(a5_1_cipher);

            Console.WriteLine("A5/1 - Text:");
            for (int i = 0; i < a5_1_text.Length; i++)
            {
                Console.Write(a5_1_text[i]);
            }
            Console.WriteLine("");

            Console.WriteLine("A5/1 - Cipher:");
            for (int i = 0; i < a5_1_cipher.Length; i++)
            {
                Console.Write(a5_1_cipher[i]);
            }
            Console.WriteLine("");

            Console.WriteLine("A5/1 - Decrypted:");
            for (int i = 0; i < a5_1_decrypted.Length; i++)
            {
                Console.Write(a5_1_decrypted[i]);
            }
            Console.WriteLine("");

            // Encrypt a file
            a5_1.GenerateTestBinaryFile();
            string a5_1_inputFilePath = "a5_1_input.bin";
            string a5_1_outputFilePath = "a5_1_encrypted.bin";
            a5_1.EncryptFile(a5_1_inputFilePath, a5_1_outputFilePath);

            // Decrypt the encrypted file
            a5_1_inputFilePath = "a5_1_encrypted.bin";
            a5_1_outputFilePath = "a5_1_decrypted.bin";
            a5_1.DecryptFile(a5_1_inputFilePath, a5_1_outputFilePath);
            Console.WriteLine("-- A5/1 - Generisani su i fajlovi --");

            //Console.WriteLine("-- A5/1 - hash vrednosti iz sha-256 klase: --");
            //Console.WriteLine("sha256 hash input fajla: " + StringHashOfTheFile("a5_1_input.bin"));
            //Console.WriteLine("sha256 hash dekriptovanog fajla: " + StringHashOfTheFile("a5_1_decrypted.bin"));
            compareTwoFilesWithSHA256("a5_1_input.bin", "a5_1_decrypted.bin");
            compareTwoFilesWithSHA256("a5_1_input.bin", "a5_1_encrypted.bin");

            a5_1.CreateBMPImage("input.bmp");
            Console.WriteLine("-- A5/1 - BMP slike --");

            Console.WriteLine("");
        }

        static void playfair()
        {
            Console.WriteLine("------ Playfair ------");

            // Playfair Cipher
            var Playfair = new Playfair("monarchy");
            string playfair_encrypted = Playfair.Encrypt("instruments");
            string playfair_decrypted = Playfair.Decrypt(playfair_encrypted);

            Console.WriteLine("Playfair - Text: instruments");
            Console.WriteLine("Playfair - Cipher: " + playfair_encrypted);
            Console.WriteLine("Playfair - Decrypted: " + playfair_decrypted);

            var Playfair_file = new Playfair("inicijativa");
            Playfair_file.EncryptFile("playfair_input.txt", "playfair_output.txt");
            Playfair_file.DecryptFile("playfair_output.txt", "playfair_decrypted.txt");
            Console.WriteLine("-- Playfair - Generisani su i fajlovi --");

            compareTwoFilesWithSHA256("playfair_input.txt", "playfair_output.txt");
            compareTwoFilesWithSHA256("playfair_input.txt", "playfair_decrypted.txt");

            var Playfair_parallel = new Playfair("inicijativa");
            Playfair_parallel.EncryptFileParallel("playfair_input.txt", "playfair_output_parallel.txt", 4);
            Playfair_parallel.DecryptFile("playfair_output_parallel.txt", "playfair_decrypted_parallel.txt");
            Console.WriteLine("-- Playfair - Paralelno enkriptovanje fajla --");

            compareTwoFilesWithSHA256("playfair_input.txt", "playfair_output_parallel.txt");
            compareTwoFilesWithSHA256("playfair_input.txt", "playfair_decrypted_parallel.txt");

            Console.WriteLine("");
        }

        static void rsa()
        {
            Console.WriteLine("------ RSA ------");
            Console.WriteLine("Generisemo kljuceve");

            // Generate a new RSA key pair
            int keySize = 48;
            RSA rsa = new RSA(keySize);

            // Get the public and private keys
            //BigInteger publicKey = rsa.PublicKey;
            //BigInteger privateKey = rsa.PrivateKey;
            //BigInteger modulus = rsa.Modulus;

            // Encrypt a message
            BigInteger message = 123456;
            Console.WriteLine("Poruka: " + message);
            BigInteger ciphertext = rsa.Encrypt(message);
            Console.WriteLine("Ciphertext: " + ciphertext);

            // Decrypt the ciphertext
            BigInteger decryptedMessage = rsa.Decrypt(ciphertext);
            Console.WriteLine("Decrypted message: " + decryptedMessage);

            //// Encrypt a file
            //string inputFilePath = "rsa_input.txt";
            //string outputFilePath = "rsa_output.txt";
            //rsa.EncryptFile(inputFilePath, outputFilePath);

            //// Decrypt the file
            //string decryptedFilePath = "rsa_decrypted.txt";
            //rsa.DecryptFile(outputFilePath, decryptedFilePath);
            //Console.WriteLine("-- RSA - Generisani su i fajlovi --");

            //rsa.CreateBMPImage("input.bmp");
            //Console.WriteLine("-- RSA - Generisana je BMP slika --");

            Console.WriteLine("");
        }

        static void cfb()
        {
            Console.WriteLine("------ CFB ------");

            //var cfbPlayfair = new CFBPlayfair("monarchy", 5, "infor");
            //string ciphertext = cfbPlayfair.Encrypt("mihajloooo");
            //string plaintext = cfbPlayfair.Decrypt(ciphertext);

            //Console.WriteLine("CFB - text: mihajloooo");
            //Console.WriteLine("CFB - encrypted: " + ciphertext);
            //Console.WriteLine("CFB - decrypted: " + plaintext);

            int[] key = { 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 
                1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 };
            int[] iv = { 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0 };
            int blockSize = 4;
            
            int[] message = { 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0 };

            // Inicijalizuj objekat klase CFB_A5_1
            CFB_A5_1 cfbCipher = new CFB_A5_1(key, iv, blockSize);

            int[] encryptedMessage = cfbCipher.Encrypt(message);
            int[] decryptedMessage = cfbCipher.Decrypt(encryptedMessage);

            //  print message, encryptedMessage and decryptedMessage
            Console.WriteLine("CFB - text: " + string.Join("", message));
            Console.WriteLine("CFB - encrypted: " + string.Join("", encryptedMessage));
            Console.WriteLine("CFB - decrypted: " + string.Join("", decryptedMessage));

            Console.WriteLine("");
        }
        static void Main(string[] args)
        {
            byte[] hash = SHA256.ComputeHash("ja sam mihajlo");
            byte[] hash2 = SHA256.ComputeHash("ja sam mihajlo2 - 123 izmena 123456789 sdfsdkfbskdlčjfbhskdjbfksldbfskldbfsdkibf");

            Console.WriteLine("SHA-256 hash vrednost: " + BitConverter.ToString(hash).Replace("-", "").ToLower());
            Console.WriteLine("SHA-256 hash2 vrednost: " + BitConverter.ToString(hash2).Replace("-", "").ToLower());


            int izbor = -1;
            do
            {
                Console.WriteLine("Izaberite algoritam: ");
                Console.WriteLine("1. A5/1");
                Console.WriteLine("2. Playfair");
                Console.WriteLine("3. RSA");
                Console.WriteLine("4. CFB (A5/1)");
                Console.WriteLine("5. Svi algoritmi");
                Console.WriteLine("6. Izlaz");
                izbor = Convert.ToInt32(Console.ReadLine());
                switch (izbor)
                {
                    case 1:
                        a5_1();
                        break;
                    case 2:
                        playfair();
                        break;
                    case 3:
                        rsa();
                        break;
                    case 4:
                        cfb();
                        break;
                    case 5:
                        a5_1();
                        playfair();
                        cfb();
                        rsa();
                        break;
                    case 6:
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine("Pogresan unos");
                        break;
                }
            } while (izbor != 5);
        }
    }
}
