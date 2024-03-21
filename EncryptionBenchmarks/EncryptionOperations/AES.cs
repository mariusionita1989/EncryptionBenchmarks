using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionBenchmarks.EncryptionOperations
{
    public static class AES
    {
        private static readonly Random random = new Random();
        private static readonly char[] alphabet = new char[] {
                                                                'A','B','C','D','E','F','G','H',
                                                                'I','J','K','L','M','N','O','P',
                                                                'Q','R','S','T','U','V','W','X',
                                                                'Y','Z','a','b','c','d','e','f'
                                                             };
        #region RandomNumberUsingRandom 
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GenerateRandomString(int length)
        {
            byte[] keyBytes = ArrayPool<byte>.Shared.Rent(length);
            Span<char> charArray = new Span<char>(new char[length]);
            int alphabetLength = alphabet.Length - 1;
            int intLength = length >> 3;
            random.NextBytes(keyBytes);

            for (int i = 0; i < intLength; i += 8)
            {
                charArray[i]   = alphabet[keyBytes[i]   & alphabetLength];
                charArray[i+1] = alphabet[keyBytes[i+1] & alphabetLength];
                charArray[i+2] = alphabet[keyBytes[i+2] & alphabetLength];
                charArray[i+3] = alphabet[keyBytes[i+3] & alphabetLength];
                charArray[i+4] = alphabet[keyBytes[i+4] & alphabetLength];
                charArray[i+5] = alphabet[keyBytes[i+5] & alphabetLength];
                charArray[i+6] = alphabet[keyBytes[i+6] & alphabetLength];
                charArray[i+7] = alphabet[keyBytes[i+7] & alphabetLength];
            }

            int remainder = length & 7;
            if (remainder != 0)
            {
                for (int i = intLength << 3; i < length; i++)
                    charArray[i] = alphabet[keyBytes[i] & alphabetLength];
            }

            ArrayPool<byte>.Shared.Return(keyBytes);
            return new string(charArray);
        }
        #endregion
       
        #region GenerateRandomHexaDecimalString
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string GenerateRandomHexaDecimalString(int length)
        {
            byte[] keyBytes = ArrayPool<byte>.Shared.Rent(length);
            int charsLength = length << 1;
            char[] charArray = ArrayPool<char>.Shared.Rent(charsLength);
            random.NextBytes(keyBytes);

            int j = 0;
            for (int i = 0; i < length; i += 2)
            {
                byte a = keyBytes[i];
                byte b = keyBytes[i+1];
                charArray[j++] = alphabet[a >> 4];
                charArray[j++] = alphabet[a & 0x0F];
                charArray[j++] = alphabet[b >> 4];
                charArray[j++] = alphabet[b & 0x0F];
            }

            if ((length & 1) != 0) 
            {
                byte a = keyBytes[length-1];
                charArray[j++] = alphabet[a >> 4];
                charArray[j++] = alphabet[a & 0x0F];
            }
                

            ArrayPool<byte>.Shared.Return(keyBytes);
            string result = new string(charArray, 0, charsLength);
            ArrayPool<char>.Shared.Return(charArray);
            return result;
        }
        #endregion

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] GenerateRandomBytes(int length = 32)
        {
            Span<byte> randomBytes = stackalloc byte[length];
            random.NextBytes(randomBytes);

            byte[] result = new byte[length];
            randomBytes.CopyTo(result);

            return result;
        }

        #region AES Encryption
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] EncryptString(string plainText, byte[] Key, byte[] IV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Convert the plain text string to bytes
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                int length = plaintextBytes.Length;
                // Create a CryptoStream to perform encryption
                using (MemoryStream msEncrypt = new MemoryStream(length))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // Write the bytes to the CryptoStream
                        csEncrypt.Write(plaintextBytes, 0, length);
                        csEncrypt.FlushFinalBlock();
                    }

                    // Return the encrypted bytes directly
                    return msEncrypt.ToArray();
                }
            }
        }
        #endregion

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string DecryptString(byte[] cipherText, byte[] Key, byte[] IV)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream msDecrypt = new MemoryStream(cipherText);
            using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using StreamReader srDecrypt = new StreamReader(csDecrypt);

            return srDecrypt.ReadToEnd();
        }
    }
}
