using System.Numerics;
using System.Runtime.CompilerServices;

namespace EncryptionBenchmarks.EncryptionOperations
{
    public static class DiffieHellman
    {
        private static readonly BigInteger P = BigInteger.Parse("9576890767");
        private static readonly BigInteger G = 2;
        private static BigInteger RangeMaxValue;
        private static BigInteger[]? precomputedPowers;
        private static Random random = new Random();
        private static int length;
        private static int keyMaxLength;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void InitializeGenerator(int size = 1024)
        {
            precomputedPowers = new BigInteger[size];
            length = precomputedPowers.Length;
            RangeMaxValue = P - 2;
            keyMaxLength = length-1;
            precomputedPowers[0] = 1;
            for (int i = 1; i < length; i++)
                precomputedPowers[i] = precomputedPowers[i - 1] * G % P;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GeneratePairOfKeys()
        {
            BigInteger alicePrivateKey = GeneratePrivateKey();
            BigInteger bobPrivateKey = GeneratePrivateKey();

            BigInteger alicePublicKey = GeneratePublicKey(alicePrivateKey);
            BigInteger bobPublicKey = GeneratePublicKey(bobPrivateKey);

            BigInteger aliceSharedSecret = ComputeSharedSecret(alicePrivateKey, bobPublicKey);
            BigInteger bobSharedSecret = ComputeSharedSecret(bobPrivateKey, alicePublicKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static BigInteger GeneratePrivateKey()
        {
            byte[] bytes = new byte[P.ToByteArray().Length];
            random.NextBytes(bytes);
            BigInteger privateKey = new BigInteger(bytes);
            return privateKey % RangeMaxValue + 2; // Ensure privateKey is within the range [2, P-1]
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static BigInteger GeneratePublicKey(BigInteger privateKey)
        {
            BigInteger value;
            int index = (int)(privateKey % keyMaxLength); // Choose index modulo array size
            if(precomputedPowers!= null)
                value = precomputedPowers[index];

            return value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static BigInteger ComputeSharedSecret(BigInteger privateKey, BigInteger otherPartyPublicKey)
        {
            return BigInteger.ModPow(otherPartyPublicKey, privateKey, P);
        }
    }
}
