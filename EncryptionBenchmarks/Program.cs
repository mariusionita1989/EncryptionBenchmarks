using BenchmarkDotNet.Running;
using EncryptionBenchmarks.Benchmark;
using EncryptionBenchmarks.EncryptionOperations;
using System.Collections;
using System.Text;

namespace EncryptionBenchmarks
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<AESEncryptionDemo>();
            BenchmarkRunner.Run<RC4EncryptionDemo>();
            BenchmarkRunner.Run<RSAEncryptionDemo>();
        }
    }
}
