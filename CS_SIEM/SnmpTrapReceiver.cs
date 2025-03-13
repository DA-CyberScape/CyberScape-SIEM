using Microsoft.Extensions.Logging;

namespace CS_SIEM;

using SnmpSharpNet;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using CS_DatabaseManager;
using System.Collections.Concurrent;
using Cassandra;
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
        _db.CreateTable("SnmpTrap", GetSnmpTrapColumnTypes(), "date, time, UUID","time DESC, UUID ASC");
    }

    /// <summary>
    /// Gets the column types for the Snmp Trap database table.
    /// </summary>
    /// <returns>A dictionary mapping column names to their types.</returns>
    public Dictionary<string, Type> GetSnmpTrapColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "source", typeof(string) },
            { "time", typeof(LocalTime) },
            { "date", typeof(LocalDate) },
            { "community", typeof(string) },
            { "trapoid", typeof(string) },
            { "variables", typeof(string) },
            { "UUID", typeof(Guid) }
        };
    }

    /// <summary>
    /// Maps Snmp Trap data to a dictionary for database insertion.
    /// </summary>
    /// <param name="snmpTrapData">The SnmpTrap data to map.</param>
    /// <returns>A dictionary containing the mapped data.</returns>
    public Dictionary<string, object> MapSnmpTrapData(SnmpTrapData snmpTrapData)
    {
        return new Dictionary<string, object>
        {
            { "source", snmpTrapData.Source },
            { "time", snmpTrapData.Time },
            { "date", snmpTrapData.Date },
            { "community", snmpTrapData.Community },
            { "trapoid", snmpTrapData.TrapOid },
            { "variables", snmpTrapData.Variables },
            { "UUID", Guid.NewGuid() }
        };
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
                    Variables = string.Empty
                };

                DateTime timestamp = DateTime.Now;
                trapData.Date = new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day);
                trapData.Time = new LocalTime(timestamp.Hour, timestamp.Minute, timestamp.Second,
                    timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000);

                var variablesBuilder = new System.Text.StringBuilder();
                foreach (Vb variable in v2Trap.Pdu.VbList)
                {
                    string oidId = variable.Oid.ToString();
                    string oidValue = variable.Value.ToString();
                    Console.WriteLine("---------------");
                    Console.WriteLine(oidId);
                    Console.WriteLine(oidValue);
                    Console.WriteLine("---------------");
                    // Append the OID and its value to the string
                    variablesBuilder.Append($"{oidId}: {oidValue}; ");
                }

                // Remove the trailing semicolon and space
                if (variablesBuilder.Length > 0)
                {
                    variablesBuilder.Length -= 2;
                }

                trapData.Variables = variablesBuilder.ToString();
                
                _snmpTraps.Enqueue(trapData);
                
                _logger.LogInformation($"Received Trap from {trapData.Source}");
                _logger.LogInformation($"Community: {trapData.Community}, OID: {trapData.TrapOid}");
                _logger.LogInformation($"Variables: {trapData.Variables}");
                _logger.LogInformation($"Time: {trapData.Date} {trapData.Time}");
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
            await InsertMessagesIntoDatabase();
        }
    }

    /// <summary>
    /// Inserts SNMP trap messages from the queue into the database.
    /// </summary>
    private async Task  InsertMessagesIntoDatabase()
    {
        _logger.LogInformation(" INSIDE THE INSERT METHOD IN SNMP TRAP");
        while (!_snmpTraps.IsEmpty)
        {
            _logger.LogInformation(" INSIDE THE INSERT METHOD IN SNMP TRAP AND THERE ARE THINGS IN THE QUEUE");

            if (_snmpTraps.TryDequeue(out SnmpTrapData trapData))
            {
                if (trapData.Community.Length > 0)
                {
                    _logger.LogInformation($"INSERTING Received Trap from {trapData.Source}");
                    _logger.LogInformation($"INSERTING Community: {trapData.Community}, OID: {trapData.TrapOid}");
                    _logger.LogInformation($"INSERTING Variables: {trapData.Variables}");
                    _logger.LogInformation($"INSERTING TIME: {trapData.Date} {trapData.Time}");


                    await InsertSnmpDataAsync(trapData, "SnmpTrap", GetSnmpTrapColumnTypes());
                }
            }
        }
    }

    /// <summary>
    /// Inserts Snmp Trap data into the appropriate database table.
    /// </summary>
    /// <param name="trapData">The Syslog message data to insert.</param>
    /// <param name="column">The column definitions for the database table.</param>
    /// <param name="columns">The columns that can be found in the database table</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public async Task InsertSnmpDataAsync(SnmpTrapData trapData,string column,
        Dictionary<string, Type> columns)
    {
        var data = MapSnmpTrapData(trapData);


        try
        {
            await _db.InsertData(column, columns, data);

        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to insert data {ex}");
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
    /// Gets or sets the concatenated string of OID variables in the format "oid_id: oid_value; ...".
    /// </summary>
    public string Variables { get; set; }

    /// <summary>
    /// Gets or sets the date of the Syslog message.
    /// </summary>
    public LocalDate? Date { get; set; }
    /// <summary>
    /// Gets or sets the time of the Syslog message.
    /// </summary>
    public LocalTime? Time { get; set; }
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

