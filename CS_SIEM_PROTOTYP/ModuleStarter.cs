﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.DependencyInjection;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;
using CsvHelper;
using CsvHelper.Configuration;
using System.Globalization;



namespace CS_SIEM_PROTOTYP;

public class ModuleStarter
{
    private SnmpPollScheduler _snmpPollScheduler;
    private NetflowScheduler _netflowScheduler;
    private SyslogScheduler _syslogScheduler;
    private SnmpTrapScheduler _snmpTrapScheduler;
    private CustomApiFetcher _customApiFetcher;
    private ApiStarter _apiStarter;
    private readonly IDatabaseManager _db;
    private readonly int _delay;
    private ILoggerFactory _loggerFactory;
    private ILogger _logger;

    private CancellationTokenSource _cancellationTokenSource;

    List<Dictionary<string, object>> _snmpPollsDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> _netflowReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> _prtgReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> _snmpTrapReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> _syslogDict = new List<Dictionary<string, object>>();
    List<CustomApiElement> _apiElements = new() {
        new CustomApiElement("https://10.0.1.254/api/v2/monitor/wifi/managed_ap", "HNrmjsgr9z9Q44rf3N1pzh8zr9kgrr"),
    };

    public ModuleStarter(IDatabaseManager db, int delay = 10)
    {
        _delay = delay;
        _db = db;
        _apiStarter = new ApiStarter(db);
        _cancellationTokenSource = new CancellationTokenSource();
        _loggerFactory = LoggerFactory.Create(builder => 
            builder
                .AddConsole()
                .SetMinimumLevel(LogLevel.Information)
                .AddFilter("Snmp Trap", LogLevel.Information)
                .AddFilter("Syslog", LogLevel.Information)
                .AddFilter("Netflow", LogLevel.Information)
                .AddFilter("Snmp Poll", LogLevel.Information)
                .AddFilter("ModuleStarter", LogLevel.Information));
        _logger = _loggerFactory.CreateLogger("ModuleStarter");
    }

    public async Task StartSIEM(string PathToJsonConfiguration)
    {
        List<SnmpPollRequest> snmpPollList = new List<SnmpPollRequest>();
        List<NfConfig> netflowList = new List<NfConfig>();
        List<PrtgConfig> prtgList = new List<PrtgConfig>();
        List<SnmpTrapConfig> snmpTrapList = new List<SnmpTrapConfig>();
        List<SyslogConfig> syslogList = new List<SyslogConfig>();
        try
        {
            _logger.LogInformation("Processing data");
            ProcessData(PathToJsonConfiguration);
            _logger.LogInformation("Finished processing data");
            snmpPollList = Converter.ConvertJsontoSnmpPollRequest(_snmpPollsDict);
            netflowList = Converter.convertJsontoNetflowDict(_netflowReceiverDict);
            prtgList = Converter.convertJsontoPRTG(_prtgReceiverDict);
            snmpTrapList = Converter.convertJsontoSNMPTrap(_snmpTrapReceiverDict);
            syslogList = Converter.ConvertJsontoSyslogConfigs(_syslogDict);
        }
        catch (Exception ex)
        {
            _logger.LogError("SUM TING WONG" + ex);
        }

        _logger.LogInformation("Converted everything correctly");
        _logger.LogInformation("Current Directory: " + Environment.CurrentDirectory);
        
        _logger.LogInformation("Turning CSV of OIDs into a Dictionary ");
        // Diese Dictionary enthaelt folgenden Daten fuer alle OIDS: IDENTIFIER, NAMEN UND DESCRIPTION
        var oidDetailsDictionary = new Dictionary<string, (string ObjectName, string Description)>();
        oidDetailsDictionary = PrepareSnmpOidDictionary("OID_CSV");
        _logger.LogInformation("Successfully turned CSV of OIDs into a Dictionary ");
        foreach (var item in oidDetailsDictionary)
        {
            _logger.LogDebug($"OID: {item.Key}, Name: {item.Value.ObjectName}, Description: {item.Value.Description}");
        }



        _logger.LogInformation("Starting the SIEM");
        if (snmpTrapList.Count > 0)
        {
            _snmpTrapScheduler = new SnmpTrapScheduler(snmpTrapList, _db, _loggerFactory.CreateLogger("Snmp Trap"),oidDetailsDictionary, _delay);
            _snmpTrapScheduler.StartAnalyzingAsync();
        }
        if (syslogList.Count > 0)
        {
            _syslogScheduler = new SyslogScheduler(syslogList, _db, _loggerFactory.CreateLogger("Syslog"), _delay);
            _syslogScheduler.StartAnalyzingAsync();
        }
        if (netflowList.Count > 0)
        {
            _netflowScheduler = new NetflowScheduler(netflowList, _db, _loggerFactory.CreateLogger("Netflow"), _delay);
            _logger.LogDebug("Netflow Scheduler start initialized");
            _netflowScheduler.StartAnalyzingAsync();
            _logger.LogDebug("Netflow Scheduler started");
        }

        if (snmpPollList.Count > 0)
        {
            _snmpPollScheduler = new SnmpPollScheduler(snmpPollList, _db, _loggerFactory.CreateLogger("Snmp Poll"),oidDetailsDictionary, _delay);
            _snmpPollScheduler.StartPollingAsync();
        }
        if (_apiElements.Count > 0)
        {
            _customApiFetcher = new CustomApiFetcher(_apiElements, _db, _loggerFactory.CreateLogger("api fetcher"));
            _customApiFetcher.StartCustomApiFetcher();
        }

        

        // await _apiStarter.StartApiAsync();
        // brauchen wir nicht mehr, da es jetzt einen dedizierten Query Server gibt

        try
        {
            await Task.Delay(Timeout.Infinite, _cancellationTokenSource.Token);
        }
        catch (TaskCanceledException)
        {
            _logger.LogInformation("The Stop SIEM Method has been called STOPPING SIEM");
        }
    }

    public void StopSIEM()
    {
        _cancellationTokenSource.Cancel();
        _logger.LogDebug($"Cancellation Token: {_cancellationTokenSource.IsCancellationRequested}");
        _logger.LogInformation("Stopping the SIEM");

        // _apiStarter.StopApi();
        // brauchen wir nicht mehr, da es jetzt einen dedizierten Query Server gibt
        // object?.stop wird nur aufgerufen wenn object nicht null ist
        _snmpPollScheduler?.StopPolling();
        _netflowScheduler?.StopPolling();
        _syslogScheduler?.StopPolling();
        _snmpTrapScheduler.StopPolling();
        _customApiFetcher.StopCustomApiFetcher();
        
        
        
        _logger.LogInformation("---------------------------------------------------");
        _logger.LogInformation("---------------------------------------------------");
        _logger.LogInformation("SIEM Stopped");
        _logger.LogInformation("---------------------------------------------------");
        _logger.LogInformation("---------------------------------------------------");
        _loggerFactory.Dispose();
    }

    public Dictionary<String, (string ObjectName, string Description)> PrepareSnmpOidDictionary(string PathToFolder)
    {
        var oidDetailsDictionary = new Dictionary<string, (string ObjectName, string Description)>();
        PathToFolder = Path.Combine(Environment.CurrentDirectory, PathToFolder);
        _logger.LogInformation("Path to the Folder of CSV with OIDs "+ PathToFolder);
        string[] csvFiles = Directory.GetFiles(PathToFolder, "*.csv");
        
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = ",",
            MissingFieldFound = null,
            TrimOptions = TrimOptions.Trim,
            HeaderValidated = null,
            HasHeaderRecord = true
        };
        
        foreach (var file in csvFiles)
        {
            _logger.LogInformation("Current CSV Files Data being extracted " + file);
            using (var reader = new StreamReader(file)) 
            using (var csv = new CsvReader(reader, config))
            {
                
                if (reader.Peek() == -1)
                {
                    _logger.LogWarning($"File {file} is empty.");
                    continue;
                }
                
                var records = csv.GetRecords<OidCsv>();
                
                foreach (var record in records)
                {
                    oidDetailsDictionary[record.OBJECT_IDENTIFIER] = (record.OBJECT_NAME, record.OBJECT_DESCRIPTION);
                }
            }
        }
        

        return oidDetailsDictionary;
    }

    private void ProcessData(string PathToJsonConfiguration)
    {
        var jsonArray = ParseJson(PathToJsonConfiguration);

        foreach (JObject item in jsonArray)
        {
            ExtractJsonProperty(item, "snmpPolls", ref _snmpPollsDict);
            ExtractJsonProperty(item, "netflowReceiver", ref _netflowReceiverDict);
            ExtractJsonProperty(item, "PRTGReceiver", ref _prtgReceiverDict);
            ExtractJsonProperty(item, "snmpTrapReceiver", ref _snmpTrapReceiverDict);
            ExtractJsonProperty(item, "Syslog", ref _syslogDict);

            if (item["ScyllaDB"] != null)
            {
                // Additional logic for ScyllaDB (if needed)
                //TODO MEHMET IRGENDWAS MIT SCYLLADB MACHEN
                // K.A was du hier haben willst sai.
            }
        }
    }

    private static JArray ParseJson(string jsonPath)
    {
        string jsonText = File.ReadAllText(jsonPath);
        return JArray.Parse(jsonText);
    }

    private static void ExtractJsonProperty(JObject item, string key, ref List<Dictionary<string, object>> targetDict)
    {
        if (item[key] != null)
        {
            targetDict = item[key].ToObject<List<Dictionary<string, object>>>();
        }
    }

    public static void PrintDictionary<T>(T dict)
    {
        Console.WriteLine(JsonConvert.SerializeObject(dict, Formatting.Indented));
        Console.WriteLine("------------------------------------");
    }

    public static async void StartPrtg(IDatabaseManager db, ServiceProvider serviceProvider, string url)
    {
        // var prtg = serviceProvider.GetService<PrtgReceiver>()!;
        // var apiKey = "5462TDSFODTTNUP36QXMQIWIQJUED5RWNC5SSVPUZQ======";
        //
        //
        // // creating and insert data into the database
        //
        // var snmpColumns = prtg.GetSensorColumnTypes();
        // string primaryKey = "UUID";
        // await db.CreateTable("SNMP", snmpColumns, primaryKey);
        //
        // // ------------------------LOOP---------------------------------
        // List<Device> devices = prtg.FetchDeviceWithSensors(url, apiKey).GetAwaiter().GetResult();
        // foreach (var device in devices)
        // {
        //     await prtg.InsertSensorsAsync(device, "SNMP", snmpColumns);
        // }
        // // ------------------------LOOP---------------------------------
    }
}