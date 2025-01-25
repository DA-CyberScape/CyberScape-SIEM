using Cassandra;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;

namespace CS_SIEM_PROTOTYP;

public class NetflowScheduler
{
    private readonly int _delay;
    private readonly List<NfConfig> _nfConfigs;
    private readonly IDatabaseManager _databaseManager;
    private CancellationTokenSource _cancellationTokenSource;
    private static List<NetFlowData> _allNetFlowData = new List<NetFlowData>();
    private ILogger _logger;

    public NetflowScheduler(List<NfConfig> nfConfigs, IDatabaseManager databaseManager, ILogger logger,
        int delayInSeconds = 10)
    {
        _nfConfigs = nfConfigs;
        _delay = delayInSeconds;
        _databaseManager = databaseManager;
        _cancellationTokenSource = new CancellationTokenSource();
        _databaseManager.CreateTable("Netflow", GetNetflowColumnTypes(), "date, time, UUID");
        _logger = logger;
    }


    public async Task StartAnalyzingAsync()
    {
        var cancellationToken = _cancellationTokenSource.Token;
        _logger.LogInformation("[INFO] Starting Netflow Scheduler...");
        int i = 1;
        while (!cancellationToken.IsCancellationRequested)
        {
            Console.WriteLine("I AM STILL STANDING AFTER ALL THIS  1");
            // Console.WriteLine($"RUN {i}");
            _logger.LogInformation("[INFO] Polling cycle started.");


            foreach (var config in _nfConfigs)
            {
                Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 2");
                _logger.LogInformation(
                    $"[INFO] Polling Netflow data for configuration ID: {config.Id}, Name: {config.Name}, Port: {config.Port}, Location: {config.FolderLocation}");

                try
                {
                    string[] netflowPaths = NetflowReceiver.GetFilePaths(config.FolderLocation);
                    
                    foreach (string nfpath in netflowPaths)
                    {
                        Console.WriteLine(nfpath);
                        // Console.WriteLine($"Hello {i}");
                        List<string> lines = NetflowReceiver.ProcessCapturedFile(nfpath, config.NfdumpBinaryLocation);
                        _allNetFlowData.AddRange(NetflowReceiver.ParseNetFlowData(lines));
                    }
                    
                    //TODO: reenable the code below later when the log generator is fully functional
                    MoveFilesToOldDirectory(config.FolderLocation, netflowPaths);

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
                Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 3");
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
                Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 4");
                _allNetFlowData = new List<NetFlowData>();
                _logger.LogInformation($"[INFO] Netflow Data from configurations has been inserted into the database.");
            }
            Console.WriteLine("I AM STILL STANDING AFTER ALL THIS TIME 5");


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


    public void MoveFilesToOldDirectory(string nfdump_files, string[] netflowPaths)
    {
        string nfDirectoryOld = nfdump_files + "/nf_files_old";
        if (!Directory.Exists(nfDirectoryOld))
        {
            Directory.CreateDirectory(nfDirectoryOld);
        }

        foreach (var nfPath in netflowPaths)
        {
            string fileName = Path.GetFileName(nfPath);
            string destFilePath = Path.Combine(nfDirectoryOld, fileName);
            try
            {
                File.Move(nfPath, destFilePath);
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

    public void StopPolling()
    {
        if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            Console.ForegroundColor = ConsoleColor.Green;
            _logger.LogInformation("[INFO] Netflow Scheduler is stopping...");
        }
    }

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
    //TODO MEHMET austesten DB

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
                Console.WriteLine(e);
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
            Console.WriteLine("TESTING 1");
            try
            {
                foreach (var d in data)
                {
                    Console.WriteLine(d.Key + " " + d.Value);
                }
                await _databaseManager.InsertData(table, columns, data);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to insert data: " + ex.Message);
            }
            Console.WriteLine("TESTING 2");
        }
        Console.WriteLine("INSERTION DONE");
    }
}