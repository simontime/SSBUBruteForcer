using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace TitlekeyBruteForcer
{
    internal static class Program
    {
        /* 
          This program is literally useless,
          because it's more likely that the moon 
          will fall out of the fucking sky 
          than it guessing the correct key. 
        */

        private static void Main(string[] args)
        {
            string TBA(byte[] Input) => BitConverter.ToString(Input).Replace("-", "").ToLower();

            // Counter uses Program RomFS modifier (2) and accounts for position @ 0x1c020 >> 4
            byte[] CtrIV     = { 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1c, 2 },
            // Block located at 0x1c020-0x1c030 in the SSBU Program NCA, which is all zeroes, so we can use a known plaintext attack.
            TargetCipherText = { 0x08, 0xd0, 0xc3, 0xcb, 0x0a, 0x8b, 0xaf, 0xc6, 0xf1, 0xe5, 0x4c, 0xc9, 0x99, 0xdb, 0x66, 0xe0 },
            // Target plaintext, as stated above, is all zeroes.
            TargetPlainText  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            KeyBuf  = new byte[16], 
            KeyBuf2 = new byte[16],
            OutBuf  = new byte[16];

            using (var RNG = new RNGCryptoServiceProvider())
            using (var Aes = new AesCryptoServiceProvider() { Mode = CipherMode.ECB, Padding = PaddingMode.None })
            {
                ulong NumTested = 0;
                while (true)
                {
                    RNG.GetBytes(KeyBuf);
                    Aes.Key = KeyBuf;

                    KeyBuf2 = Aes.CreateEncryptor().TransformFinalBlock(CtrIV, 0, 16);

                    for (int j = 0; j < 16; j++)
                        OutBuf[j] = (byte)(KeyBuf2[j] ^ TargetCipherText[j]);

                    if (OutBuf.SequenceEqual(TargetPlainText))
                    {
                        var Text = $"Key: {TBA(KeyBuf)}";
                        File.WriteAllText("extractedkey.txt", Text);
                        Console.WriteLine(Text);
                        break;
                    }

                    if (++NumTested % 10000 == 0)
                        Console.Write($"\rKeys tested: {NumTested:n0}");
                }
            }
        }
    }
}