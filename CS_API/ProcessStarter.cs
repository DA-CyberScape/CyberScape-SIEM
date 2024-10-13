using System.Diagnostics;
// https://dev.to/tkarropoulos/cancellation-tokens-in-c-cm0
//TODO https://chatgpt.com/share/67057d0a-8fb8-8000-9442-3064c7e072af
namespace CS_API;

public static class ProcessStarter
{
    private static CancellationTokenSource? _cts = null;
    private static Task? _currentTask = null;

    public static async Task StartProcessAsync(string configPath, CancellationToken cancellationToken)
    {
        if (!File.Exists(configPath))
        {
            throw new FileNotFoundException($"Configuration file '{configPath}' not found.");
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _currentTask = Task.Run(async () =>
        {
            Console.WriteLine($"Starting process with configuration: {configPath}");
            var configContent = File.ReadAllText(configPath);

            while (!token.IsCancellationRequested)
            {
                Console.WriteLine($"Processing configuration: {configContent}");
                await Task.Delay(5000, token); // Simulate work being done periodically
            }

            Console.WriteLine("Process stopped.");
        }, cancellationToken);

        await _currentTask;
    }

    public static void StopProcess()
    {
        if (_cts == null || _currentTask == null)
        {
            Console.WriteLine("No process is currently running.");
            return;
        }

        try
        {
            Console.WriteLine("Stopping process...");
            _cts.Cancel();
            _currentTask.Wait();
            _cts = null;
            _currentTask = null;
        }
        catch (Exception e)
        {
            Console.WriteLine("PROCESS STOPPED");
        }

        
    }
}
