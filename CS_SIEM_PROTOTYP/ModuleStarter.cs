using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.DependencyInjection;
using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP;

public class ModuleStarter
{
    private SnmpPollScheduler _snmpPollScheduler;
    private NetflowScheduler _netflowScheduler;
    private SyslogScheduler _syslogScheduler;
    private ApiStarter _apiStarter;
    private readonly IDatabaseManager _db;
    private readonly int _delay;

    private CancellationTokenSource _cancellationTokenSource;

    List<Dictionary<string, object>> snmpPollsDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> netflowReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> prtgReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> snmpTrapReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> syslogDict = new List<Dictionary<string, object>>();

    public ModuleStarter(IDatabaseManager db, int delay = 10)
    {
        _delay = delay;
        _db = db;
        _apiStarter = new ApiStarter(db);
        _cancellationTokenSource = new CancellationTokenSource();
    }

    public async Task StartSIEM(string PathToJsonConfiguration)
    {
        ProcessData(PathToJsonConfiguration);

        List<SnmpPollRequest> snmpPollList = Converter.convertJsontoSNMPPollRequest(snmpPollsDict);
        List<NfConfig> netflowList = Converter.convertJsontoNetflowDict(netflowReceiverDict);
        List<PrtgConfig> prtgList = Converter.convertJsontoPRTG(prtgReceiverDict);
        List<SnmpTrapConfig> snmpTrapList = Converter.convertJsontoSNMPTrap(snmpTrapReceiverDict);
        List<SyslogConfig> syslogList = Converter.ConvertJsontoSyslogConfigs(syslogDict);

        Console.WriteLine("[INFO] Starting the SIEM");

        
        if (syslogList.Count > 0)
        {
            _syslogScheduler = new SyslogScheduler(syslogList, _db, _delay);
            _syslogScheduler.StartAnalyzingAsync();
        }
        if (netflowList.Count > 0)
        {
            _netflowScheduler = new NetflowScheduler(netflowList, _db, _delay);
            _netflowScheduler.StartAnalyzingAsync();
        }

        if (snmpPollList.Count > 0)
        {
            _snmpPollScheduler = new SnmpPollScheduler(snmpPollList, _db, _delay);
            _snmpPollScheduler.StartPollingAsync();
        }

        

        _apiStarter.StartApiAsync();

        try
        {
            await Task.Delay(Timeout.Infinite, _cancellationTokenSource.Token);
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("[INFO] The Stop SIEM Method has been called STOPPING SIEM");
        }
    }

    public void StopSIEM()
    {
        Console.WriteLine("[INFO] Stopping the SIEM");
        _cancellationTokenSource.Cancel();

        _apiStarter.StopApi();
        _snmpPollScheduler?.StopPolling();
        _netflowScheduler?.StopPolling();
        _syslogScheduler?.StopPolling();

        Console.WriteLine("[INFO] SIEM Stopped");
    }

    private void ProcessData(string PathToJsonConfiguration)
    {
        var jsonArray = ParseJson(PathToJsonConfiguration);

        foreach (JObject item in jsonArray)
        {
            ExtractJsonProperty(item, "snmpPolls", ref snmpPollsDict);
            ExtractJsonProperty(item, "netflowReceiver", ref netflowReceiverDict);
            ExtractJsonProperty(item, "PRTGReceiver", ref prtgReceiverDict);
            ExtractJsonProperty(item, "snmpTrapReceiver", ref snmpTrapReceiverDict);
            ExtractJsonProperty(item, "Syslog", ref syslogDict);

            if (item["ScyllaDB"] != null)
            {
                // Additional logic for ScyllaDB (if needed)
                //TODO MEHMET IRGENDWAS MIT SCYLLADB MACHEN
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
        var prtg = serviceProvider.GetService<PrtgReceiver>()!;
        var apiKey = "5462TDSFODTTNUP36QXMQIWIQJUED5RWNC5SSVPUZQ======";


        // creating and insert data into the database

        var snmpColumns = prtg.GetSensorColumnTypes();
        string primaryKey = "UUID";
        await db.CreateTable("SNMP", snmpColumns, primaryKey);

        // ------------------------LOOP---------------------------------
        List<Device> devices = prtg.FetchDeviceWithSensors(url, apiKey).GetAwaiter().GetResult();
        foreach (var device in devices)
        {
            await prtg.InsertSensorsAsync(device, "SNMP", snmpColumns);
        }
        // ------------------------LOOP---------------------------------
    }
}