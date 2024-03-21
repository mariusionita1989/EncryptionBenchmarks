using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace EncryptionBenchmarks.EncryptionOperations
{
    public static class RSACipher
    {
        private static readonly Random random = new Random();
        private static RSACryptoServiceProvider? rsa;
        private static byte[]? output;
        private static byte[]? input;
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
                charArray[i] = alphabet[keyBytes[i] & alphabetLength];
                charArray[i + 1] = alphabet[keyBytes[i + 1] & alphabetLength];
                charArray[i + 2] = alphabet[keyBytes[i + 2] & alphabetLength];
                charArray[i + 3] = alphabet[keyBytes[i + 3] & alphabetLength];
                charArray[i + 4] = alphabet[keyBytes[i + 4] & alphabetLength];
                charArray[i + 5] = alphabet[keyBytes[i + 5] & alphabetLength];
                charArray[i + 6] = alphabet[keyBytes[i + 6] & alphabetLength];
                charArray[i + 7] = alphabet[keyBytes[i + 7] & alphabetLength];
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] GenerateRandomBytes(int length = 32)
        {
            Span<byte> randomBytes = stackalloc byte[length];
            random.NextBytes(randomBytes);
            byte[] result = new byte[length];
            randomBytes.CopyTo(result);

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GenerateKey()
        {
            rsa = new RSACryptoServiceProvider(2048); // Generate a new 2048 bit RSA key
            rsa.PersistKeyInCsp = false; // Don't store the key in a container
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Encrypt(byte[] data) 
        {
            output = Array.Empty<byte>();
            if (rsa != null)
              output = rsa.Encrypt(data, true);

            return output;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Decrypt(byte[] data)
        {
            input = Array.Empty<byte>();
            if (rsa != null)
              input = rsa.Decrypt(data, true);

            return input;
        }
    }
}
