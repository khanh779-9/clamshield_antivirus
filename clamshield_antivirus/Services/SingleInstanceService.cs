using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace clamshield_antivirus.Services;

public class SingleInstanceService : IDisposable
{
    private const string MutexName = "ClamUI_SingleInstance_Mutex";
    private const string PipeName = "ClamUI_Pipe";
    private Mutex? _mutex;
    private bool _isFirstInstance;
    private CancellationTokenSource? _cts;

    public event Action<string>? ScanPathReceived;

    public bool TryRun(string[] args)
    {
        _mutex = new Mutex(true, MutexName, out _isFirstInstance);

        if (_isFirstInstance)
        {
            _cts = new CancellationTokenSource();
            _ = ListenForPathsAsync(_cts.Token);
            return true;
        }

        SendPaths(args);
        return false;
    }

    private static void SendPaths(string[] args)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(2000);
            using var writer = new StreamWriter(client);

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("--scan", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    writer.WriteLine(args[i + 1]);
                    i++;
                }
            }
            writer.Flush();
        }
        catch (TimeoutException) { }
        catch (IOException) { }
    }

    private async Task ListenForPathsAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1);
                await server.WaitForConnectionAsync(token);

                using var reader = new StreamReader(server);
                string? line;
                while ((line = await reader.ReadLineAsync(token)) != null)
                {
                    if (!string.IsNullOrEmpty(line))
                    {
                        ScanPathReceived?.Invoke(line);
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (IOException) { }
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _mutex?.Dispose();
    }
}
