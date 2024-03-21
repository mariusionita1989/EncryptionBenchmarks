using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using EncryptionBenchmarks.EncryptionOperations;

namespace EncryptionBenchmarks.Benchmark
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class RSAEncryptionDemo
    {
        private int length = 128;
        private byte[]? input;
        private byte[]? output;

        [GlobalSetup]
        public void Setup()
        {
            RSACipher.GenerateKey();
            input = RSACipher.GenerateRandomBytes(length);
        }

        [Benchmark]
        public void EncryptBenchmark()
        {
            if(input != null)
                output = RSACipher.Encrypt(input);
        }

        [Benchmark]
        public void DecryptBenchmark()
        {
            if (output != null) 
                input = RSACipher.Decrypt(output);
        }
    }
}
