using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using EncryptionBenchmarks.EncryptionOperations;

namespace EncryptionBenchmarks.Benchmark
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class RC4EncryptionDemo
    {
        private const int length = 1024 * 1024;
        private byte[]? input;
        private byte[]? key;

        [GlobalSetup]
        public void GlobalSetup()
        {
            input = RC4.GenerateRandomBytes(length);
            key = RC4.GenerateRandomBytes();
        }

        [Benchmark]
        public void RC4Apply()
        {
            if (input != null && key != null)
            {
                var str = RC4.Apply(input, key);
            }
        }
    }
}
