using Microsoft.Extensions.Logging;

namespace CS_SIEM_PROTOTYP;

using SnmpSharpNet;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using CS_DatabaseManager;
using System.Collections.Concurrent;
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
    
    public SnmpTrapReceiver(IDatabaseManager db, ILogger logger,Dictionary<string, (string ObjectName, string Description)> oidDictionary, int port = 162, int delay = 10)
    {
        
        _db = db;
        _delay = delay;
        _port = port;
        _logger = logger;
        _oidDictionary = oidDictionary;
    }



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
                    Variables = new Dictionary<string, string>()
                };

                foreach (Vb variable in v2Trap.Pdu.VbList)
                {
                    trapData.Variables[variable.Oid.ToString()] = variable.Value.ToString();
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
    public void StopReceiver()
    {
        cancellationTokenSource.Cancel();
        _logger.LogInformation($"[INFO] SNMP Trap Receiver shutdown initiated... {cancellationTokenSource.IsCancellationRequested}");
        udpClient?.Close();
    }

    
}

public class SnmpTrapData
{
    public string Source { get; set; }
    public string Community { get; set; }
    public string TrapOid { get; set; }
    public Dictionary<string, string> Variables { get; set; }
}


public class SnmpTrapConfig
{
    public int Port { get; set; }
    public string Name { get; set; }
    public int Id { get; set; }

    public override string ToString()
    {
        return $"Port: {Port}, Id: {Id}, Name: {Name}";
    }
}

