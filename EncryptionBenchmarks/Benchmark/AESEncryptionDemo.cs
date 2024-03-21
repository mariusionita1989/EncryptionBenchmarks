using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using EncryptionBenchmarks.EncryptionOperations;

namespace EncryptionBenchmarks.Benchmark
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class AESEncryptionDemo
    {
        private const int length = 1024 * 1024;
        private string input = string.Empty;
        private byte[]? key;
        private byte[]? iv;
        private byte[]? output;

        [GlobalSetup]
        public void GlobalSetup()
        {
            input = AES.GenerateRandomString(length);
            key = AES.GenerateRandomBytes();
            iv = AES.GenerateRandomBytes(16);
            output = AES.EncryptString(input,key,iv);
        }

        [Benchmark]
        public void GenerateRandomString()
        {
            if (output != null && key != null && iv != null) 
            {
                var str = AES.DecryptString(output, key, iv);
            }
        }
    }
}
