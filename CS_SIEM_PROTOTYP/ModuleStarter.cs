namespace CS_SIEM_PROTOTYP;
using CS_DatabaseManager;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class ModuleStarter
{
    private SnmpPollScheduler _snmpPollScheduler;
    private NetflowScheduler _netflowScheduler;
    private ApiStarter _apiStarter;
    List<Dictionary<string, object>> snmpPollsDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> netflowReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> prtgReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> snmpTrapReceiverDict = new List<Dictionary<string, object>>();
    List<Dictionary<string, object>> syslogDict = new List<Dictionary<string, object>>();
    
    public async void StartSIEM(string PathToJsonConfiguration)
    {
        // Teilt die ganze Konfiguration in einzelne Teile auf
        ProcessData(PathToJsonConfiguration);
        
        //OUTPUT TESTING
        // PrintDictionary(snmpPollsDict);
        // PrintDictionary(netflowReceiverDict);
        // PrintDictionary(prtgReceiverDict);
        // PrintDictionary(snmpTrapReceiverDict);
        // PrintDictionary(syslogDict);
        
        
        //Wandelt die einzelne Konfiguration in Listen von den bestimmten Receiver/Polls
        List<SnmpPollRequest> snmpPollList = Converter.convertJsontoSNMPPollRequest(snmpPollsDict);
        List<NfConfig> netflowList = Converter.convertJsontoNetflowDict(netflowReceiverDict);
        List<PrtgConfig> prtgList = Converter.convertJsontoPRTG(prtgReceiverDict);
        List<SnmpTrapConfig> snmpTrapList = Converter.convertJsontoSNMPTrap(snmpTrapReceiverDict);
        List<SyslogConfig> syslogList = Converter.ConvertJsontoSyslogConfigs(syslogDict);
        
        Console.WriteLine(snmpPollList.Count);
        Console.WriteLine(netflowList.Count);
        Console.WriteLine(prtgList.Count);
        Console.WriteLine(snmpTrapList.Count);
        Console.WriteLine(syslogList.Count);
    }
    


    public void StopSIEM()
    {
    }

    public void ProcessData(string PathToJsonConfiguration)
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
                // scyllaDbDict = item["ScyllaDB"].ToObject<Dictionary<string, object>>();
                //TODO MEHMET IRGENDWAS MIT SCYLLADB MACHEN
            }
        }
        
    }
    
    public static JArray ParseJson(string jsonPath)
    {
        string jsonText = File.ReadAllText(jsonPath);
        
        JArray jsonResult = JArray.Parse(jsonText);
    
        return jsonResult; 
    }
    
    public void ExtractJsonProperty(JObject item, string key, ref List<Dictionary<string, object>> targetDict)
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