using CS_DatabaseManager;
using Microsoft.Extensions.Logging;
using Cassandra;
namespace CS_SIEM;

/// <summary>
/// Schedules and manages the execution of the NetFlow receiver.
/// Commands the Netflow receiver to extract the data from files in the specified folder depending on the configuration format the data and then discard the file.
/// </summary>
public class NetflowScheduler
{
    private readonly int _delay;
    private readonly List<NfConfig> _nfConfigs;
    private readonly IDatabaseManager _databaseManager;
    private CancellationTokenSource _cancellationTokenSource;
    private static List<NetFlowData> _allNetFlowData = new List<NetFlowData>();
    private ILogger _logger;

    /// <summary>
    /// Initializes the NetflowScheduler Class
    /// </summary>
    /// <param name="nfConfigs">the list of Netflow configurations that should be used</param>
    /// <param name="databaseManager">Database manager instance to handle database operations.</param>
    /// <param name="logger">Logger instance for logging operations.</param>
    /// <param name="delayInSeconds">time between the extraction of data</param>
    public NetflowScheduler(List<NfConfig> nfConfigs, IDatabaseManager databaseManager, ILogger logger,
        int delayInSeconds = 10)
    {
        _nfConfigs = nfConfigs;
        _delay = delayInSeconds;
        _databaseManager = databaseManager;
        _cancellationTokenSource = new CancellationTokenSource();
        _databaseManager.CreateTable("Netflow", GetNetflowColumnTypes(), "date, time, UUID","time DESC, UUID ASC");
        _logger = logger;
    }


    /// <summary>
    /// Starts the process of data extraction, data formatation and file deletion
    /// </summary>
    public async Task StartAnalyzingAsync()
    {
        var cancellationToken = _cancellationTokenSource.Token;
        _logger.LogInformation("[INFO] Starting Netflow Scheduler...");
        int i = 1;
        while (!cancellationToken.IsCancellationRequested)
        {
            // Console.WriteLine("I AM STILL STANDING AFTER ALL THIS  1");
            // Console.WriteLine($"RUN {i}");
            _logger.LogInformation("[INFO] Polling cycle started.");


            foreach (var config in _nfConfigs)
            {
                // Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 2");
                _logger.LogInformation(
                    $"[INFO] Polling Netflow data for configuration ID: {config.Id}, Name: {config.Name}, Port: {config.Port}, Location: {config.FolderLocation}");

                try
                {
                    string[] netflowPaths = NetflowAnalyzer.GetFilePaths(config.FolderLocation);
                    
                    foreach (string nfpath in netflowPaths)
                    {
                        // Console.WriteLine(nfpath);
                        // Console.WriteLine($"Hello {i}");
                        List<string> lines = NetflowAnalyzer.ProcessCapturedFile(nfpath, config.NfdumpBinaryLocation);
                        _allNetFlowData.AddRange(NetflowAnalyzer.ParseNetFlowData(lines));
                    }
                    
                    //TODO: reenable the code below later when the log generator is fully functional
                    DeleteUsedNetflowFiles(netflowPaths);

                    if (_allNetFlowData.Count > 0)
                    {
                        _logger.LogInformation(
                            $"[INFO] Successfully polled {_allNetFlowData.Count} Entries for configuration ID: {config.Id}, Location: {config.FolderLocation}");
                    }
                }
                catch (Exception ex) when (!(ex is TaskCanceledException))
                {
                    _logger.LogError(
                        $"[ERROR] Error while polling data for configuration ID: {config.Id}: {ex.Message}");
                }
                // Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 3");
            }


            /*
            foreach (var nfdata in _allNetFlowData)
            {
                Console.WriteLine(nfdata);
            }*/
            if (_allNetFlowData.Count > 0)
            {
                _logger.LogInformation("[INFO] Inserting Netflow data into the database...");
                await InsertNfDataAsync(_allNetFlowData, "Netflow", GetNetflowColumnTypes());

                _allNetFlowData = new List<NetFlowData>();
                _logger.LogInformation($"[INFO] Netflow Data from configurations has been inserted into the database.");
            }
            // Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 5");


            _logger.LogInformation("[INFO] Netflow Polling cycle completed. Waiting for the next interval...");
            try
            {
                _logger.LogInformation($"[INFO] Netflow Waiting for {_delay} seconds");
                await Task.Delay(_delay * 1000, cancellationToken);
                _logger.LogInformation("[INFO] Netflow Delay completed, resuming polling cycle...");
            }
            catch (TaskCanceledException)
            {
                _logger.LogInformation("[INFO] Netflow Polling has been canceled.");
                break;
            }
        }

        _logger.LogInformation("[INFO] Netflow Scheduler stopped.");
    }


    /// <summary>
    /// Deletes used netflow files
    /// </summary>
    /// <param name="netflowPaths">list of paths to the files that should be deleted</param>
    public void DeleteUsedNetflowFiles(string[] netflowPaths)
    {


        foreach (var nfPath in netflowPaths)
        {
            try
            {
                File.Delete(nfPath);
            }
            catch (IOException ioEx)
            {
                _logger.LogError($"I/O error occurred: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error occurred: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Stops the process
    /// </summary>
    public void StopPolling()
    {
        if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            _logger.LogInformation("[INFO] Netflow Scheduler is stopping...");
        }
    }

    /// <summary>
    /// Maps the Netflow data to a dictionary for database insertion.
    /// </summary>
    /// <param name="nfData">Netflow data object</param>
    /// <returns>A dictionary representation of the Netflow data</returns>
    public Dictionary<string, object> MapnfDataToData(NetFlowData nfData)
    {
        return new Dictionary<string, object>
        {
            { "srcIP", nfData.srcIP },
            { "dstIP", nfData.dstIP },
            { "srcPort", nfData.srcPort },
            { "dstPort", nfData.dstPort },
            { "bytes", nfData.bytes },
            { "time", nfData.time },
            { "date", nfData.date},
            { "duration", nfData.duration },
            { "protocol", nfData.protocol },
            { "flag", nfData.flag },
            { "typeOfService", nfData.typeOfService },
            { "packets", nfData.packets },
            { "flows", nfData.flows },
            { "icmpType", nfData.icmpType },
            { "UUID", Guid.NewGuid() }
        };
    }

    /// <summary>
    /// Defines the database column types for Netflow data.
    /// </summary>
    /// <returns>A dictionary mapping column names to data types.</returns>
    public Dictionary<string, Type> GetNetflowColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "srcIP", typeof(string) },
            { "dstIP", typeof(string) },
            { "srcPort", typeof(int) },
            { "dstPort", typeof(int) },
            { "bytes", typeof(long) },
            { "time", typeof(LocalTime) },
            { "date", typeof(LocalDate)},
            { "duration", typeof(Duration) },
            { "protocol", typeof(string) },
            { "flag", typeof(string) },
            { "typeOfService", typeof(int) },
            { "packets", typeof(int) },
            { "flows", typeof(int) },
            { "icmpType", typeof(double) },
            { "UUID", typeof(Guid) }
        };
    }

    /// <summary>
    /// Inserts Netflow data into the database.
    /// </summary>
    /// <param name="nfDatas">list of netflow data objects</param>
    /// <param name="table">Database table name.</param>
    /// <param name="columns">Column definitions.</param>
    public async Task InsertNfDataAsync(List<NetFlowData> nfDatas, string table, Dictionary<string, Type> columns)
    {
        foreach (var nfData in nfDatas)
        {
    
            var data = new Dictionary<string, object>();
            try
            {
                data = MapnfDataToData(nfData);
            }
            catch(Exception e)
            {
                // Console.WriteLine(e);
            }




            // _logger.LogDebug("Begin Row");
            // // _logger.LogDebug(nfData.duration.ToString());
            // //
            // foreach (var value in data)
            // {
            //     Console.Write(value + " --- ");
            // }
            // Console.WriteLine();
            // _logger.LogDebug("End Row");
            // Console.WriteLine("TESTING 1");
            try
            {
              
                await _databaseManager.InsertData(table, columns, data);
            }
            catch (Exception ex)
            {
                // _logger.LogError($"Failed to insert data: " + ex.Message);
            }
           
        }
        _logger.LogInformation("Database Insertion complete");
        // Console.WriteLine("INSERTION DONE");
    }
}