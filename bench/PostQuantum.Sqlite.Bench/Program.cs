using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

// Allow running a subset by name from the command line, e.g.:
//   dotnet run -c Release --project bench/PostQuantum.Sqlite.Bench -- --filter "*Create*"
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, DefaultConfig.Instance);

internal sealed partial class Program { }
