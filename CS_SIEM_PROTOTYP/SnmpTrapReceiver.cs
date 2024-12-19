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
    
    public SnmpTrapReceiver(IDatabaseManager db, int port = 162, int delay = 10)
    {
        
        _db = db;
        _delay = delay;
        _port = port;
    }



    public async Task StartListening()
    {
        try
        {
            Console.WriteLine($"Attempting to bind to port {_port}...");
    
            // Bind the client to the specified port
            udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, _port));
            Console.WriteLine($"Successfully bound to port {_port}. Listening for SNMPv2c traps...");
    
            // Start periodic database insertion
            _ = Task.Run(() => StartPeriodicDatabaseInsert(_delay, cancellationToken), cancellationToken);
    
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Block until a message is received
                    UdpReceiveResult result = await udpClient.ReceiveAsync();
    
                    // Process the received trap
                    ProcessTrap(result.Buffer, result.RemoteEndPoint);
                }
                catch (SocketException se)
                {
                    Console.WriteLine($"[Socket Error] {se.Message}");
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Error] {ex.Message}");
                }
            }
        }
        catch (SocketException se)
        {
            Console.WriteLine($"[Error] Could not bind to port {_port}: {se.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Unexpected error: {ex.Message}");
        }
        finally
        {
            udpClient?.Close();
            Console.WriteLine("UDP client closed.");
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
                
                Console.WriteLine($"Received Trap from {trapData.Source}");
                Console.WriteLine($"Community: {trapData.Community}, OID: {trapData.TrapOid}");
                foreach (var kvp in trapData.Variables)
                {
                    Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing trap: {ex.Message}");
        }
    }
    
    private async Task StartPeriodicDatabaseInsert(int delay, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(1000 * delay, token);
            Console.WriteLine("INSERTING EVERYTH(ING S:DLFKJSD:LFKJSD:LFKJSD:FLKJSDF");
            Console.WriteLine(_snmpTraps.Count + " THIS WAS THE COUNT");
            InsertMessagesIntoDatabase();
        }
    }
    
    private void InsertMessagesIntoDatabase()
    {
        Console.WriteLine(" INSIDE THE INSERT METHOD IN SNMP TRAP");
        while (!_snmpTraps.IsEmpty)
        {
            Console.WriteLine(" INSIDE THE INSERT METHOD IN SNMP TRAP AND THERE ARE THINGS IN THE QUEUE");

            if (_snmpTraps.TryDequeue(out SnmpTrapData trapData))
            {
                if (trapData.Community.Length > 0)
                {
                    Console.WriteLine($"Received Trap from {trapData.Source}");
                    Console.WriteLine($"Community: {trapData.Community}, OID: {trapData.TrapOid}");
                    foreach (var kvp in trapData.Variables)
                    {
                        Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
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
        Console.WriteLine("[INFO] SNMP Trap Receiver shutdown initiated...");
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

