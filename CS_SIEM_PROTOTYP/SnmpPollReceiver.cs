using Cassandra;

namespace CS_SIEM_PROTOTYP;

using CS_DatabaseManager;
using System;
using SnmpSharpNet;
using static CS_SIEM_PROTOTYP.SnmpPollSender;

/// <summary>
/// Class that provides functionality to receive SNMP polls using SNMPv3.
/// </summary>
public class SnmpPollReceiver
{


    /// <summary>
    /// Polls SNMPv3 devices based on the provided SNMP request and OID dictionary.
    /// </summary>
    /// <param name="snmpRequest">The SNMP request containing the OIDs, IP address, and other SNMPv3 parameters.</param>
    /// <param name="oidDictionary">A dictionary mapping OIDs to their corresponding names and descriptions.</param>
    /// <returns>A list of <see cref="SnmpPoll"/> objects containing the polled data.</returns>
    /// <exception cref="Exception">Thrown when an error occurs during the polling process.</exception>
    public static List<SnmpPoll> PollSnmpV3(SnmpPollRequest snmpRequest,
        Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        List<SnmpPoll> answerSnmpPolls = new List<SnmpPoll>();
        try
        {
            foreach (var entry in snmpRequest.Oids)
            {
                string baseOid = entry.Key;
                string baseName = entry.Value;
                if (baseOid.EndsWith(".x"))
                {
                    baseOid = baseOid.Substring(0, baseOid.Length - 2);
                    var answerSnmpElement = WalkSnmpV3(baseOid, snmpRequest.IpAddress, snmpRequest.User, snmpRequest.AuthPass,
                        snmpRequest.PrivPass, snmpRequest.Port, snmpRequest.Hostname, snmpRequest.Authentication,
                        snmpRequest.Encryption, baseName, oidDictionary);
                    answerSnmpPolls.AddRange(answerSnmpElement);
                   
                    
                }
                else
                {
                    var answerSnmpElement = GetSnmpV3(baseOid, snmpRequest.IpAddress, snmpRequest.User, snmpRequest.AuthPass,
                                            snmpRequest.PrivPass, snmpRequest.Port, snmpRequest.Hostname, snmpRequest.Authentication,
                                            snmpRequest.Encryption, baseName, oidDictionary);
                    answerSnmpPolls.AddRange(answerSnmpElement);
                   
                }

            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: " + ex.Message);
            
        }

        return answerSnmpPolls;
    }

}

/// <summary>
/// Represents an SNMP poll request containing OIDs, device information, and SNMPv3 credentials.
/// This is the data received from the management website after getting processed.
/// </summary>
public class SnmpPollRequest
{
    /// <summary>
    /// Gets or sets the OIDs to be polled along with their names.
    /// </summary>
    public Dictionary<string, string> Oids { get; set; }
    /// <summary>
    /// Gets or sets the IP address of the SNMP device.
    /// </summary>
    public string IpAddress { get; set; }
    /// <summary>
    /// Gets or sets the hostname of the SNMP device.
    /// </summary>
    public string Hostname { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 username.
    /// </summary>

    public string User { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 authentication password.
    /// </summary>
    public string AuthPass { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 privacy password.
    /// </summary>
    public string PrivPass { get; set; }
    /// <summary>
    /// Gets or sets the port number for the SNMP request.
    /// </summary>
    public int Port { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 authentication digest algorithm.
    /// </summary>
    public AuthenticationDigests AuthDigest { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 privacy protocol.
    /// </summary>
    public PrivacyProtocols PrivProtocol { get; set; }
    /// <summary>
    /// Gets or sets the name of the SNMP request.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// Gets or sets the ID of the SNMP request.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 authentication type.
    /// </summary>
    public string Authentication { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 encryption type.
    /// </summary>
    public string Encryption { get; set; }


    /// <summary>
    /// Initializes a new instance of the <see cref="SnmpPollRequest"/> class with specified parameters.
    /// </summary>
    /// <param name="oids">The OIDs to be polled.</param>
    /// <param name="ipAddress">The IP address of the SNMP device.</param>
    /// <param name="user">The SNMPv3 username.</param>
    /// <param name="authPass">The SNMPv3 authentication password.</param>
    /// <param name="privPass">The SNMPv3 privacy password.</param>
    /// <param name="authDigest">The SNMPv3 authentication digest algorithm.</param>
    /// <param name="privProtocol">The SNMPv3 privacy protocol.</param>
    /// <param name="port">The port number for the SNMP request.</param>
    /// <param name="hostname">The hostname of the SNMP device.</param>
    public SnmpPollRequest(Dictionary<string, string> oids, string ipAddress, string user, string authPass,
        string privPass,
        AuthenticationDigests authDigest, PrivacyProtocols privProtocol, int port, string hostname)
    {
        Oids = oids;
        Port = port;
        Hostname = hostname;
        IpAddress = ipAddress;
        User = user;
        AuthPass = authPass;
        PrivPass = privPass;
        AuthDigest = authDigest;
        PrivProtocol = privProtocol;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SnmpPollRequest"/> class.
    /// </summary>
    public SnmpPollRequest()
    {
        Oids = new Dictionary<string, string>(); // damit man kein null reference fehler bekommt
    }

    /// <summary>
    /// Returns a string representation of the SNMP poll request.
    /// </summary>
    /// <returns>A string containing the details of the SNMP poll request.</returns>
    public override string ToString()
    {
        // Start building the output string
        string oidsString = "";
        foreach (var oid in Oids)
        {
            oidsString += $"OID: {oid.Key}, Name: {oid.Value}\n";
        }

        return $"Hostname: {Hostname}, IP Address: {IpAddress}, Port: {Port}\n" +
               $"User: {User}, AuthPass: {AuthPass}, PrivPass: {PrivPass}\n" +
               $"Authentication: {AuthDigest}, Encryption: {PrivProtocol}\n" +
               $"OIDs:\n{oidsString} id: {Id} name: {Name} ";
    }
}

/// <summary>
/// Represents the result of an SNMP poll.
/// </summary>
public class SnmpPoll
{
    /// <summary>
    /// Gets or sets the IP address of the polled device.
    /// </summary>
    public string IpAddress { get; set; }
    /// <summary>
    /// Gets or sets the OID that was polled.
    /// </summary>
    public string Oid { get; set; }
    /// <summary>
    /// Gets or sets the value of the polled OID.
    /// </summary>
    public string OidValue { get; set; }
    /// <summary>
    /// Gets or sets the hostname of the polled device.
    /// </summary>

    public string Hostname { get; set; }
    /// <summary>
    /// Gets or sets the name of the polled OID.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// Gets or sets the time when the poll was performed.
    /// </summary>
    public LocalTime Time { get; set; }
    /// <summary>
    /// Gets or sets the date when the poll was performed.
    /// </summary>
    public LocalDate Date { get; set; }


    /// <summary>
    /// Initializes a new instance of the <see cref="SnmpPoll"/> class with specified parameters.
    /// </summary>
    /// <param name="ipAddress">The IP address of the polled device.</param>
    /// <param name="oid">The OID that was polled.</param>
    /// <param name="oidValue">The value of the polled OID.</param>
    /// <param name="hostname">The hostname of the polled device.</param>
    /// <param name="time">The time when the poll was performed.</param>
    /// <param name="date">The date when the poll was performed.</param>
    /// <param name="name">The name of the polled OID.</param>
    public SnmpPoll(string ipAddress, string oid, string oidValue, string hostname, LocalTime time, LocalDate date,
        string name)
    {
        IpAddress = ipAddress;
        Oid = oid;
        OidValue = oidValue;
        Hostname = hostname;
        Time = time;
        Date = date;
        Name = name;
    }


    /// <summary>
    /// Returns a string representation of the SNMP poll result.
    /// </summary>
    /// <returns>A string containing the details of the SNMP poll result.</returns>
    public override string ToString()
    {
        return $"SNMP Poll [IP Address: {IpAddress}, OID: {Oid}, OID Value: {OidValue}, " +
               $"Hostname: {Hostname}, Time: {Time}, Date: {Date}, Name: {Name}]";
    }
}

/// <summary>
/// Represents an SNMP OID with its corresponding name.
/// </summary>
public class SnmpOid
{
    /// <summary>
    /// Gets or sets the OID.
    /// </summary>
    public string oid { get; set; }
    /// <summary>
    /// Gets or sets the name of the OID.
    /// </summary>
    public string name { get; set; }
}

/// <summary>
/// Represents an SNMP device with its configuration and OIDs to be polled.
/// Used to extract data directly from the JSON, same variables as the JSON from the management website.
/// </summary>
public class SnmpDevice
{
    /// <summary>
    /// Gets or sets the IP address of the SNMP device.
    /// </summary>
    public string ip { get; set; }
    /// <summary>
    /// Gets or sets the hostname of the SNMP device.
    /// </summary>
    public string hostname { get; set; }
    /// <summary>
    /// Gets or sets the list of OIDs to be polled on the device.
    /// </summary>
    public List<SnmpOid> oids { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 username.
    /// </summary>
    public string user { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 authentication type.
    /// </summary>
    public string authentication { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 encryption type.
    /// </summary>
    public string encryption { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 authentication password.
    /// </summary>
    public string authpass { get; set; }
    /// <summary>
    /// Gets or sets the SNMPv3 privacy password.
    /// </summary>
    public string privpass { get; set; }
    /// <summary>
    /// Gets or sets the port number for the SNMP request.
    /// </summary>
    public int port { get; set; }
    /// <summary>
    /// Gets or sets the name of the SNMP device.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// Gets or sets the ID of the SNMP device.
    /// </summary>
    public int Id { get; set; }
}