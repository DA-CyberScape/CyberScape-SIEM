using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using CS_DatabaseManager;

namespace CS_API;

/// <summary>
/// Class responsible for updating the "Vlans" table in the database with data from the JSON String
/// received via API POST Request from the Management Website
/// </summary>
public class VlanTableUpdater
{
    private readonly string _json;

    /// <summary>
    /// Initializes a new instance of the <see cref="VlanTableUpdater"/> class with the provided JSON String.
    /// </summary>
    /// <param name="json">The JSON string containing the VLAN data received from the management website</param>
    public VlanTableUpdater(string json)
    {
        _json = json;
    }

    /// <summary>
    /// Updates the "Vlans" table by deleting it, recreating it, and inserting the new data from the JSON string.
    /// References:
    /// <see cref="ExtractVlanData"/> for extracting VLAN data from the JSON string.
    /// <see cref="GetVlansColumnTypes"/> for obtaining the column types for the "Vlans" table.
    /// <see cref="MapVlanDataToData"/> for mapping <see cref="Vlan"/> objects to column data.
    /// </summary>
    public async void UpdateVlanTable()
    {
        List<Vlan> data = ExtractVlanData();
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        await db.DeleteTable("Vlans");
        await db.CreateTable("Vlans", GetVlansColumnTypes(), "network", null);

        foreach (var element in data)
        {
            await db.InsertData("Vlans", GetVlansColumnTypes(), MapVlanDataToData(element));
        }
    }

    /// <summary>
    /// Creates the "Vlans" table with the appropriate column types and primary key.
    /// References:
    /// <see cref="GetVlansColumnTypes"/> for obtaining the column types for the "Vlans" table.
    /// </summary>
    public async static void CreateTable()
    {
        var dbHost = new DbHostProvider();
        IDatabaseManager db = new ScyllaDatabaseManager(dbHost);
        await db.CreateTable("Vlans", GetVlansColumnTypes(), "network", null);
    }

    /// <summary>
    /// Extracts a list of VLANs from the provided JSON string.
    /// </summary>
    /// <returns>A list of <see cref="Vlan"/> objects with network, subnet mask, and name.</returns>
    public List<Vlan> ExtractVlanData()
    {
        var vlanList = new List<Vlan>();

        using var doc = JsonDocument.Parse(_json);
        var root = doc.RootElement;
        var vlans = root.GetProperty("vlans");
        foreach (JsonElement vlan in vlans.EnumerateArray())
        {
            Vlan v = new Vlan(
                vlan.GetProperty("network").GetString(),
                vlan.GetProperty("subnetmask").GetString(),
                vlan.GetProperty("name").GetString()
            );
            vlanList.Add(v);
        }

        foreach (var item in vlanList)
        {
            Console.WriteLine($"Network: {item.Network}, Subnet Mask: {item.SubnetMask}, Name: {item.Name}");
        }
        return vlanList;
    }

    /// <summary>
    /// Returns the column names and types for the "Vlans" table.
    /// </summary>
    /// <returns>A dictionary mapping column names to their respective data types.</returns>
    public static Dictionary<string, Type> GetVlansColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "network", typeof(string) },
            { "subnetmask", typeof(string) },
            { "name", typeof(string) }
        };
    }

    /// <summary>
    /// Maps a <see cref="Vlan"/> object to a dictionary of column names and corresponding values.
    /// </summary>
    /// <param name="vlan">The <see cref="Vlan"/> object to map.</param>
    /// <returns>A dictionary representing the column names and values for the VLAN.</returns>
    public Dictionary<string, object> MapVlanDataToData(Vlan vlan)
    {
        return new Dictionary<string, object>
        {
            { "network", vlan.Network },
            { "subnetmask", vlan.SubnetMask },
            { "name", vlan.Name }
        };
    }
}

/// <summary>
/// Represents a VLAN with a network, subnet mask, and name.
/// </summary>
public class Vlan
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Vlan"/> class with the provided information.
    /// </summary>
    /// <param name="network">The network address of the VLAN.</param>
    /// <param name="subnetMask">The subnet mask of the VLAN.</param>
    /// <param name="name">The name of the VLAN.</param>
    public Vlan(string network, string subnetMask, string name)
    {
        Network = network;
        SubnetMask = subnetMask;
        Name = name;
    }

    /// <summary>
    /// Gets or sets the network address of the VLAN.
    /// </summary>
    public string Network { get; set; }

    /// <summary>
    /// Gets or sets the subnet mask of the VLAN.
    /// </summary>
    public string SubnetMask { get; set; }

    /// <summary>
    /// Gets or sets the name of the VLAN.
    /// </summary>
    public string Name { get; set; }
}