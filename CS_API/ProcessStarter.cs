using System.Diagnostics;
using CS_DatabaseManager;

// https://dev.to/tkarropoulos/cancellation-tokens-in-c-cm0
//TODO https://chatgpt.com/share/67057d0a-8fb8-8000-9442-3064c7e072af
namespace CS_API;

using CS_SIEM_PROTOTYP;

public static class ProcessStarter
{
    private static CancellationTokenSource? _cts = null;
    private static Task? _currentTask = null;
    private static ModuleStarter _moduleStarter;

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
            
            DbHostProvider dbHost = new DbHostProvider();
            IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
            _moduleStarter = new ModuleStarter(db, 10);
            var siemTask =
                _moduleStarter.StartSIEM(
                    @"/home/cyberscape_admin/CyberScape-SIEM/CS_API/Configurations_Example/example_API.json");
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
            // _cts.Cancel();
            _moduleStarter.StopSIEM();
            _currentTask.Wait();
            Console.WriteLine(
                "STOPPED J:LSDKFJS:DLKFJSD:LFKJSDLFKJSD:FLKJSD:FLKJSD:FLKSJD:FLKSJDF:LSKDJF:SLDKJFS:DLKJF");
            _cts = null;
            _currentTask = null;
        }
        catch (Exception e)
        {
            Console.WriteLine("PROCESS STOPPED");
        }
    }
}