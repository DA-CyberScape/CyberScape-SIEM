using Microsoft.Extensions.Logging;

namespace CS_SIEM;

using SnmpSharpNet;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using CS_DatabaseManager;
using System.Collections.Concurrent;
/// <summary>
/// Receives and processes SNMP traps from network devices.
/// </summary>
public class SnmpTrapReceiver
{
    // Class variable to store received SNMP traps
    private static ConcurrentQueue<SnmpTrapData> _snmpTraps = new ConcurrentQueue<SnmpTrapData>();
    private static int _delay = 10;
    private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
    private static CancellationToken cancellationToken = cancellationTokenSource.Token;
    private static UdpClient udpClient;
    private IDatabaseManager _db;
    private int _port;
    private ILogger _logger;
    private Dictionary<string, (string ObjectName, string Description)> _oidDictionary;

    /// <summary>
    /// Initializes a new instance of the <see cref="SnmpTrapReceiver"/> class.
    /// </summary>
    /// <param name="db">The database manager for inserting received SNMP traps.</param>
    /// <param name="logger">The logger for logging information and errors.</param>
    /// <param name="oidDictionary">A dictionary mapping OIDs to their corresponding names and descriptions.</param>
    /// <param name="port">The port to listen for SNMP traps. Default is 162.</param>
    /// <param name="delay">The delay in seconds between inserting SNMP traps. Default is 10 seconds.</param>
    public SnmpTrapReceiver(IDatabaseManager db, ILogger logger,Dictionary<string, (string ObjectName, string Description)> oidDictionary, int port = 162, int delay = 10)
    {
        
        _db = db;
        _delay = delay;
        _port = port;
        _logger = logger;
        _oidDictionary = oidDictionary;
    }



    /// <summary>
    /// Starts listening for SNMPv2c traps on the specified port.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public async Task StartListening()
    {
        try
        {
            cancellationToken = new CancellationToken();
            _logger.LogInformation($"Attempting to bind to port {_port}...");
    
            // Bind the client to the specified port
            udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, _port));
            _logger.LogInformation($"Successfully bound to port {_port}. Listening for SNMPv2c traps...");
    
            // Start periodic database insertion
            _ = Task.Run(() => StartPeriodicDatabaseInsert(_delay, cancellationToken), cancellationToken);
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    _logger.LogDebug($"Cancellation Token inside WHILE: {cancellationToken.IsCancellationRequested}");
                    // Block until a message is received
                    UdpReceiveResult result = await udpClient.ReceiveAsync();
    
                    // Process the received trap
                    ProcessTrap(result.Buffer, result.RemoteEndPoint);
                }
                catch (SocketException se)
                {
                    _logger.LogError($"[Socket Error] {se.Message}");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"[Error] {ex.Message}");
                }
            }
        }
        catch (SocketException se)
        {
            _logger.LogError($"[Error] Could not bind to port {_port}: {se.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError($"[Error] Unexpected error: {ex.Message}");
        }
        finally
        {
            _logger.LogInformation("UDP client close initiated.");
            udpClient?.Close();
            _logger.LogInformation("UDP client closed.");
        }
    }


    /// <summary>
    /// Processes a received SNMP trap.
    /// </summary>
    /// <param name="trapBytes">The raw bytes of the SNMP trap.</param>
    /// <param name="source">The source IP endpoint of the trap.</param>
    private void ProcessTrap(byte[] trapBytes, IPEndPoint source)
    {
        try
        {
            // Parse the SNMP message
            SnmpPacket snmpPacket = new SnmpV2Packet();
            snmpPacket.decode(trapBytes, trapBytes.Length);

            if (snmpPacket.Pdu.Type == PduType.V2Trap)
            {
                SnmpV2Packet v2Trap = (SnmpV2Packet)snmpPacket;

                SnmpTrapData trapData = new SnmpTrapData
                {
                    Source = source.Address.ToString(),
                    Community = v2Trap.Community.ToString(),
                    TrapOid = v2Trap.Pdu.TrapObjectID.ToString(),
                    Variables = new Dictionary<string, (string OidName, string OidValue)>()
                };

                foreach (Vb variable in v2Trap.Pdu.VbList)
                {
                    string oidName = "unknown";
                    string oidId = variable.Oid.ToString();
                    string oidValue = variable.Value.ToString();
                    if (_oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(oidId), out var wert1))
                    {
                        oidName = wert1.ObjectName;
                        
                        Console.WriteLine($"OID NAME: {oidName} OID ID: {oidId} OID VALUE: {oidValue}");
                    }
                    trapData.Variables[oidId] = (oidName, oidValue);
                }
                
                _snmpTraps.Enqueue(trapData);
                
                _logger.LogInformation($"Received Trap from {trapData.Source}");
                _logger.LogInformation($"Community: {trapData.Community}, OID: {trapData.TrapOid}");
                foreach (var kvp in trapData.Variables)
                {
                    _logger.LogInformation($"  {kvp.Key}: {kvp.Value}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error processing trap: {ex.Message}");
        }
    }
    /// <summary>
    /// Removes the last two characters from a string if it ends with "0".
    /// Used to get a name from the OID Dictionary if the specific name is null
    /// </summary>
    /// <param name="input">The input string.</param>
    /// <returns>The modified string.</returns>
    public static string RemoveLastTwoIfEndsWithZero(string input)
    {
        if (input.EndsWith("0") && input.Length >= 2)
        {
            return input.Substring(0, input.Length - 2);
        }
        return input; 
    }

    /// <summary>
    /// Starts periodic insertion of SNMP traps into the database.
    /// </summary>
    /// <param name="delay">The delay in seconds between insertions.</param>
    /// <param name="token">The cancellation token to stop the task.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    private async Task StartPeriodicDatabaseInsert(int delay, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(1000 * delay, token);
            _logger.LogInformation("INSERTING EVERYTH(ING S:DLFKJSD:LFKJSD:LFKJSD:FLKJSDF");
            _logger.LogInformation(_snmpTraps.Count + " THIS WAS THE COUNT");
            InsertMessagesIntoDatabase();
        }
    }

    /// <summary>
    /// Inserts SNMP trap messages from the queue into the database.
    /// </summary>
    private void InsertMessagesIntoDatabase()
    {
        _logger.LogInformation(" INSIDE THE INSERT METHOD IN SNMP TRAP");
        while (!_snmpTraps.IsEmpty)
        {
            _logger.LogInformation(" INSIDE THE INSERT METHOD IN SNMP TRAP AND THERE ARE THINGS IN THE QUEUE");

            if (_snmpTraps.TryDequeue(out SnmpTrapData trapData))
            {
                if (trapData.Community.Length > 0)
                {
                    _logger.LogInformation($"Received Trap from {trapData.Source}");
                    _logger.LogInformation($"Community: {trapData.Community}, OID: {trapData.TrapOid}");
                    foreach (var kvp in trapData.Variables)
                    {
                        _logger.LogInformation($"  {kvp.Key}: {kvp.Value}");
                    }

                    // TODO: MEHMET DB LOGIK
                    // InsertSyslogDataAsync(syslogMessage, "Syslog", GetSyslogColumnTypes());
                }
            }
        }
    }
    /// <summary>
    /// Stops the SNMP trap receiver and cancels the listening task.
    /// </summary>
    public void StopReceiver()
    {
        cancellationTokenSource.Cancel();
        _logger.LogInformation($"[INFO] SNMP Trap Receiver shutdown initiated... {cancellationTokenSource.IsCancellationRequested}");
        udpClient?.Close();
    }

    
}

/// <summary>
/// Represents the data of an SNMP trap.
/// </summary>
public class SnmpTrapData
{
    /// <summary>
    /// Gets or sets the source IP address of the trap.
    /// </summary>
    public string Source { get; set; }
    /// <summary>
    /// Gets or sets the community string of the trap.
    /// </summary>
    public string Community { get; set; }
    /// <summary>
    /// Gets or sets the trap OID.
    /// </summary>
    public string TrapOid { get; set; }
    /// <summary>
    /// Gets or sets the variables included in the trap.
    /// </summary>
    public Dictionary<string, (string OidName, string OidValue)> Variables { get; set; }
}


/// <summary>
/// Represents the configuration for an SNMP trap receiver.
/// </summary>
public class SnmpTrapConfig
{
    // <summary>
    /// Gets or sets the port to listen for SNMP traps.
    /// </summary>
    public int Port { get; set; }
    /// <summary>
    /// Gets or sets the name of the SNMP trap receiver.
    /// </summary>

    public string Name { get; set; }
    /// <summary>
    /// Gets or sets the ID of the SNMP trap receiver.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Returns a string representation of the SNMP trap configuration.
    /// </summary>
    /// <returns>A string containing the port, ID, and name of the configuration.</returns>
    public override string ToString()
    {
        return $"Port: {Port}, Id: {Id}, Name: {Name}";
    }
}

