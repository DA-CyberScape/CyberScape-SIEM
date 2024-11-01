﻿using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP;

public class NetflowScheduler
{
    private readonly int _delay;
    private readonly List<NfConfig> _nfConfigs;
    private readonly IDatabaseManager _databaseManager;
    private CancellationTokenSource _cancellationTokenSource;
    private static List<NetFlowData> _allNetFlowData = new List<NetFlowData>();

    public NetflowScheduler(List<NfConfig> nfConfigs, IDatabaseManager databaseManager, int delayInSeconds = 10)
    {
        _nfConfigs = nfConfigs;
        _delay = delayInSeconds;
        _databaseManager = databaseManager;
        _cancellationTokenSource = new CancellationTokenSource();
    }


    public async Task StartAnalyzingAsync()
    {
        var cancellationToken = _cancellationTokenSource.Token;
        Console.WriteLine("[INFO] Starting Netflow Scheduler...");

        while (!cancellationToken.IsCancellationRequested)
        {
            Console.WriteLine("[INFO] Polling cycle started.");


            foreach (var config in _nfConfigs)
            {
                Console.WriteLine(
                    $"[INFO] Polling Netflow data for configuration ID: {config.Id}, Name: {config.Name}, Port: {config.Port}, Location: {config.FolderLocation}");

                try
                {
                    string[] netflowPaths = NetflowReceiver.GetFilePaths(config.FolderLocation);
                    foreach (string nfpath in netflowPaths)
                    {
                        List<string> lines = NetflowReceiver.ProcessCapturedFile(nfpath, config.NfdumpBinaryLocation);
                        _allNetFlowData.AddRange(NetflowReceiver.ParseNetFlowData(lines));
                        MoveFilesToOldDirectory(config.FolderLocation, netflowPaths);
                    }

                    if (_allNetFlowData.Count > 0)
                    {
                        Console.WriteLine(
                            $"[INFO] Successfully polled {_allNetFlowData.Count} Entries for configuration ID: {config.Id}, Location: {config.FolderLocation}");
                    }
                }
                catch (Exception ex) when (!(ex is TaskCanceledException))
                {
                    Console.WriteLine(
                        $"[ERROR] Error while polling data for configuration ID: {config.Id}: {ex.Message}");
                }
            }


            /*
            foreach (var nfdata in _allNetFlowData)
            {
                Console.WriteLine(nfdata);
            }*/
            if (_allNetFlowData.Count > 0)
            {
                Console.WriteLine("[INFO] Inserting Netflow data into the database...");
                // await InsertNfDataAsync(_allNetFlowData, "Netflow", GetNetflowColumnTypes());
                //TODO INSERT DATA INTO DATABASE
                _allNetFlowData = new List<NetFlowData>();
                Console.WriteLine($"[INFO] Data from configurations has been inserted into the database.");
            }


            Console.WriteLine("[INFO] Polling cycle completed. Waiting for the next interval...");
            try
            {
                Console.WriteLine($"[INFO] Waiting for {_delay} seconds");
                await Task.Delay(_delay * 1000, cancellationToken);
                Console.WriteLine("[INFO] Delay completed, resuming polling cycle...");
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("[INFO] Polling has been canceled.");
                break;
            }
        }

        Console.WriteLine("[INFO] Netflow Scheduler stopped.");
    }


    public void MoveFilesToOldDirectory(string nfdump_files, string[] netflowPaths)
    {
        string nfDirectoryOld = nfdump_files + "/nf_files_old";
        if (!Directory.Exists(nfDirectoryOld))
        {
            Directory.CreateDirectory(nfDirectoryOld);
        }

        Console.ForegroundColor = ConsoleColor.Red;
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
                Console.WriteLine($"I/O error occurred: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred: {ex.Message}");
            }
        }
    }

    public void StopPolling()
    {
        if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[INFO] Netflow Scheduler is stopping...");
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
            { "timestamp", nfData.timestamp },
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
            { "timestamp", typeof(DateTime) },
            { "duration", typeof(DateTime) },
            { "protocol", typeof(string) },
            { "flag", typeof(string) },
            { "typeOfService", typeof(int) },
            { "packets", typeof(int) },
            { "flows", typeof(int) },
            { "icmpType", typeof(double) },
            { "UUID", typeof(Guid) }
        };
    }

    public async Task InsertNfDataAsync(List<NetFlowData> nfDatas, string table, Dictionary<string, Type> columns)
    {
        foreach (var nfData in nfDatas)
        {
            var data = MapnfDataToData(nfData);

            foreach (var value in data)
            {
                Console.WriteLine(value);
            }

            try
            {
                await _databaseManager.InsertData(table, columns, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to insert data");
            }
        }
    }
}