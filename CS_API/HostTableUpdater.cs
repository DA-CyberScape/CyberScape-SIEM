using System.Text.Json;
using System.Text.Json.Serialization;
using CS_DatabaseManager;

namespace CS_API;

public class HostTableUpdater
{
    private readonly string _json;

    public HostTableUpdater(string json)
    {
        _json = json;
    }


    public async void UpdateHostTable()
    {
        List<Host> data = ExtractNameIpList();
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        // db.DeleteData();
        await db.CreateTable("Hosts", GetHostsColumnTypes(), "ip", null);

        foreach (var element in data)
        {
            await db.InsertData("Hosts", GetHostsColumnTypes(), MapHostDataToData(element));
        }

    }
    public async static void CreateTable()
    {
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        await db.CreateTable("Hosts", GetHostsColumnTypes(), "ip", null);

    }

    public List<Host> ExtractNameIpList()
    {
        var hostnameIpList = new List<Host>();


        using var doc = JsonDocument.Parse(_json);
        var root = doc.RootElement;
        var assignments = root.GetProperty("assignments");
        foreach (JsonElement assignment in assignments.EnumerateArray())
        {
            Host h = new Host();  
            h.Hostname = assignment.GetProperty("hostname").GetString();
            h.IpAddress = assignment.GetProperty("ipAddress").GetString();
            hostnameIpList.Add(h);
        }
        
        foreach (var item in hostnameIpList)
        {
            Console.WriteLine($"Hostname: {item.Hostname}, IP Address: {item.IpAddress}");
        }
        return hostnameIpList;
    }
    public static Dictionary<string, Type> GetHostsColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "hostname", typeof(string) },
            { "ip", typeof(string) },
           
        };
    }
    public Dictionary<string, object> MapHostDataToData(Host host)
    {
        return new Dictionary<string, object>
        {
            { "hostname", host.Hostname },
            {"ip", host.IpAddress }
        };
    }
    
}

public class Host
{

    public string Hostname { get; set; }
    public string IpAddress { get; set; }
}
