using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _17743_Mihajlo_Marjanovic_ZI_Projekat
{
    class CFBPlayfair
    {
        private readonly Playfair _playfair;
        private readonly int _blockSize;
        private readonly string _iv;

        public CFBPlayfair(string key, int blockSize, string iv)
        {
            _playfair = new Playfair(key);
            _blockSize = blockSize;
            _iv = iv;
        }

        public string Encrypt(string plaintext)
        {
            var ciphertext = new StringBuilder();
            var previousCipherBlock = _iv;

            for (int i = 0; i < plaintext.Length; i += _blockSize)
            {
                var plainBlock = plaintext.Substring(i, _blockSize);
                var cipherBlock = _playfair.Encrypt(previousCipherBlock);
                var xorResult = XOR(plainBlock, cipherBlock);

                ciphertext.Append(xorResult);
                previousCipherBlock = xorResult;
            }

            return ciphertext.ToString();
        }

        public string Decrypt(string ciphertext)
        {
            var plaintext = new StringBuilder();
            var previousCipherBlock = _iv;

            for (int i = 0; i < ciphertext.Length; i += _blockSize)
            {
                var cipherBlock = ciphertext.Substring(i, _blockSize);
                var plainBlock = _playfair.Encrypt(previousCipherBlock);
                var xorResult = XOR(cipherBlock, plainBlock);

                plaintext.Append(xorResult);
                previousCipherBlock = cipherBlock;
            }

            return plaintext.ToString();
        }

        private string XOR(string s1, string s2)
        {
            var result = new StringBuilder();

            for (int i = 0; i < s1.Length; i++)
            {
                var c = (char)((s1[i] - 'a') ^ (s2[i] - 'a') + 'a');
                if (c < 'a' || c > 'z')
                {
                    if (c == 'x')
                    {
                        // If the resulting character is an 'x', XOR it with 'a' instead of 'z'
                        c = (char)(c ^ 'a');
                    }
                    else
                    {
                        c = (char)(c - 'a' + 'z');
                    }
                }
                result.Append(c);
            }

            return result.ToString();
        }
    }
}
