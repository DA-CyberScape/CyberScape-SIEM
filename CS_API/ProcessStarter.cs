using System.Diagnostics;
using CS_DatabaseManager;
using CS_SIEM_PROTOTYP;

// https://dev.to/tkarropoulos/cancellation-tokens-in-c-cm0
//TODO https://chatgpt.com/share/67057d0a-8fb8-8000-9442-3064c7e072af
namespace CS_API
{

    /// <summary>
    /// Provides classes and methods for interacting with the CS_API.
    /// </summary>
    internal static class NamespaceDoc
    {
        // Documentation for the namespace
    }


    /// <summary>
    /// Represents a class responsible for starting and stopping the database manager and the module starter which starts all the configured modules
    /// </summary>
    public class ProcessStarter
    {
        private static CancellationTokenSource? _cts = null;
        private static Task? _currentTask = null;
        private ModuleStarter _moduleStarter;

        /// <summary>
        /// Starts a the database manager and the module starter process with the given configuration
        /// </summary>
        /// <param name="configPath">The file path of the configuration file to use for the module starter process</param>
        /// <param name="cancellationToken">A token used to cancel async tasks</param>
        /// <exception cref="FileNotFoundException">Thrown if the specified configuration file is not found</exception>
        public async Task StartProcessAsync(string configPath, CancellationToken cancellationToken)
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
                    _moduleStarter.StartSiem(
                        configPath);
                return siemTask;
            }, cancellationToken);

            await _currentTask;
        }
        /// <summary>
        /// Stops the currently running process, if there is one
        /// </summary>

        public void StopProcess()
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
                Console.WriteLine(_currentTask.Status);
                _moduleStarter.StopSiem();
                Console.WriteLine(_currentTask.Status);
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

}