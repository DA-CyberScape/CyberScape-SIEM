using System.Text.Json;
using System.Text.Json.Serialization;
using CS_DatabaseManager;

namespace CS_API;

/// <summary>
/// Class responsible for updating the "Hosts" table in the database with data from the JSON String
/// received via API POST Request from the Management Website
/// </summary>
public class HostTableUpdater
{
    private readonly string _json;

    /// <summary>
    /// Initializes a new instance of the <see cref="HostTableUpdater"/> class with the provided JSON String.
    /// </summary>
    /// <param name="json">The JSON string containing the host data received from the management website</param>
    public HostTableUpdater(string json)
    {
        _json = json;
    }


    /// <summary>
    /// Updates the "Hosts" table by deleting it, recreating it, and inserting the new data from the JSON string.
    /// References:
    /// <see cref="ExtractNameIpList"/> for extracting host data from the JSON string.
    /// <see cref="GetHostsColumnTypes"/> for obtaining the column types for the "Hosts" table.
    /// <see cref="MapHostDataToData"/> for mapping <see cref="Host"/> objects to column data.
    /// </summary>
    public async void UpdateHostTable()
    {
        List<Host> data = ExtractNameIpList();
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        await db.DeleteTable("Hosts");
        await db.CreateTable("Hosts", GetHostsColumnTypes(), "ip", null);

        foreach (var element in data)
        {
            await db.InsertData("Hosts", GetHostsColumnTypes(), MapHostDataToData(element));
        }

    }
    /// <summary>
    /// Creates the "Hosts" table with the appropriate column types and primary key.
    /// References:
    /// <see cref="GetHostsColumnTypes"/> for obtaining the column types for the "Hosts" table.
    /// </summary>
    public async static void CreateTable()
    {
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        await db.CreateTable("Hosts", GetHostsColumnTypes(), "ip", null);

    }

    /// <summary>
    /// Extracts a list of hosts from the provided JSON string.
    /// </summary>
    /// <returns>A list of <see cref="Host"/> objects with hostname and IP address.</returns>
    public List<Host> ExtractNameIpList()
    {
        var hostnameIpList = new List<Host>();


        using var doc = JsonDocument.Parse(_json);
        var root = doc.RootElement;
        var assignments = root.GetProperty("assignments");
        foreach (JsonElement assignment in assignments.EnumerateArray())
        {
            Host h = new Host(
                assignment.GetProperty("hostname").GetString(),
                assignment.GetProperty("ipAddress").GetString(),
                assignment.GetProperty("device_type").GetString()
            );
            hostnameIpList.Add(h);
        }
        
        foreach (var item in hostnameIpList)
        {
            Console.WriteLine($"Hostname: {item.Hostname}, IP Address: {item.IpAddress}");
        }
        return hostnameIpList;
    }
    /// <summary>
    /// Returns the column names and types for the "Hosts" table.
    /// </summary>
    /// <returns>A dictionary mapping column names to their respective data types.</returns>
    public static Dictionary<string, Type> GetHostsColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "hostname", typeof(string) },
            { "ip", typeof(string) },
            { "device_type", typeof(string) }
        };
    }
    /// <summary>
    /// Maps a <see cref="Host"/> object to a dictionary of column names and corresponding values.
    /// </summary>
    /// <param name="host">The <see cref="Host"/> object to map.</param>
    /// <returns>A dictionary representing the column names and values for the host.</returns>
    public Dictionary<string, object> MapHostDataToData(Host host)
    {
        return new Dictionary<string, object>
        {
            { "hostname", host.Hostname },
            {"ip", host.IpAddress },
            { "device_type", host.DeviceType }
        };
    }
    
}

/// <summary>
/// Represents a host with a hostname, an IP address, and a device type.
/// </summary>
public class Host
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Host"/> class with the provided information.
    /// </summary>
    /// <param name="hostname">The hostname of the host.</param>
    /// <param name="ipAddress">The IP address of the host.</param>
    /// <param name="deviceType">The device type of the host.</param>
    public Host(string hostname, string ipAddress, string deviceType)
    {
        Hostname = hostname;
        IpAddress = ipAddress;
        DeviceType = deviceType;
    }

    /// <summary>
    /// Gets or sets the hostname of the host.
    /// </summary>
    public string Hostname { get; set; }
    /// <summary>
    /// Gets or sets the IP address of the host.
    /// </summary>
    public string IpAddress { get; set; }
    /// <summary>
    /// Gets or sets the device type of the host.
    /// </summary>
    public string DeviceType { get; set; }
}
