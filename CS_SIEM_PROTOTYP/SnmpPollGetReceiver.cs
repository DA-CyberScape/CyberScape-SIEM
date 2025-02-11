using Cassandra;

namespace CS_SIEM_PROTOTYP;

using CS_DatabaseManager;
using System;
using SnmpSharpNet;
using static CS_SIEM_PROTOTYP.SnmpPoller;

//https://github.com/rqx110/SnmpSharpNet/wiki
public class SnmpPollGetReceiver
{

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


    public static List<SnmpPoll> DepicatedPollSnmpV3(SnmpPollRequest snmpRequest, Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        return DepicatedPollSnmpV3(snmpRequest.Oids, snmpRequest.IpAddress, snmpRequest.User, snmpRequest.AuthPass,
            snmpRequest.PrivPass, snmpRequest.AuthDigest, snmpRequest.PrivProtocol, snmpRequest.Port,
            snmpRequest.Hostname, oidDictionary);
    }

    public static List<SnmpPoll> DepicatedPollSnmpV3(Dictionary<string, string> oidDict, string ipAddress, string user,
        string authPass, string privPass, AuthenticationDigests authenticationDigests,
        PrivacyProtocols privacyProtocols, int port, string hostname, Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        try
        {
            // Set up the SNMP target with port 161 and a timeout
            UdpTarget target = new UdpTarget((System.Net.IPAddress)new IpAddress(ipAddress), port, 2000, 1);
            SecureAgentParameters param = new SecureAgentParameters();

            if (!target.Discovery(param))
            {
                Console.WriteLine("Discovery failed. Unable to continue...");
                target.Close();
                return null;
            }

            // Prepare the secure parameters for SNMPv3
            param.authPriv(user, authenticationDigests, authPass, privacyProtocols, privPass);

            List<SnmpPoll> answerSnmpPolls = new List<SnmpPoll>();

            // Process each OID in the dictionary
            var listOfgetRequests = new List<(string, string)>();
            foreach (var entry in oidDict)
            {
                
                string baseOid = entry.Key;
                string baseName = entry.Value;
                listOfgetRequests.Add((baseOid, baseName));

                // Check if the OID does not end with ".0"
                if (!baseOid.EndsWith(".0"))
                {
                    // Loop to append ".x" to the base OID where x ranges from 0 to 30, -1 being the normal oid
                    for (int x = -1; x <= 30; x++)
                    {
                        string modifiedOid = $"{baseOid}.{x}";
                        if (x < 0)
                        {
                            modifiedOid = baseOid;
                            
                        }
                        

                        

                        // Prepare PDU for the modified OID
                        Pdu pdu = new Pdu(PduType.Get);
                        pdu.VbList.Add(modifiedOid);

                        // Execute the SNMP request
                        SnmpV3Packet result = (SnmpV3Packet)target.Request(pdu, param);

                        // Check for valid response
                        if (result != null && result.Pdu.ErrorStatus == 0)
                        {
                            // Add to list if no error and valid response
                            foreach (var value in result.Pdu.VbList)
                            {
                                string value_string = value.Value.ToString();
                                if (!value_string.Equals("SNMP No-Such-Instance"))
                                {
                                    string oidValue = value.Oid.ToString();
                                    string modifiedName = "";
                                    if (oidDictionary.TryGetValue(oidValue, out var wert1))
                                    {
                                        modifiedName = wert1.ObjectName;
                                        
                                        // Console.WriteLine($"1ObjectName: {modifiedName} OID: {oidValue}");
                                    }else if (oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(oidValue), out var wert2))
                                    {
                                        modifiedName = wert2.ObjectName;
                                        
                                        // Console.WriteLine($"2ObjectName: {modifiedName} OID: {oidValue}");
                                        
                                    }else if (oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(baseOid), out var wert3))
                                    {
                                         modifiedName = wert3.ObjectName;

                                         // Console.WriteLine($"3ObjectName: {modifiedName} OID: {oidValue}");
                                    }
                                    else
                                    {
                                        modifiedName = $"{baseName}.{x}"; 
                                        // Console.WriteLine($"4ObjectName: {modifiedName} OID: {oidValue}");

                                    }


                                    var timestamp = DateTime.Now;
                                    SnmpPoll snmpPoll = new SnmpPoll(ipAddress, oidValue,
                                        value_string, hostname, new LocalTime(timestamp.Hour, timestamp.Minute,
                                            timestamp.Second,
                                            timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                                        new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), modifiedName);
                                    answerSnmpPolls.Add(snmpPoll);
                                }
                            }
                        }
                        else
                        {
                            // Skip if "No Such Instance" error or other error
                            Console.WriteLine($"OID {modifiedOid} not found or instance doesn't exist.");
                        }
                    }
                }
                else // eigentlich unnoetig
                {
                   
                    Pdu pdu = new Pdu(PduType.Get);
                    pdu.VbList.Add(baseOid);

                    // Execute the SNMP request
                    SnmpV3Packet result = (SnmpV3Packet)target.Request(pdu, param);

                    if (result != null && result.Pdu.ErrorStatus == 0)
                    {
                        // Add to list if no error and valid response
                        foreach (var value in result.Pdu.VbList)
                        {
                            string value_string = value.Value.ToString();
                            if (!value_string.Equals("SNMP No-Such-Instance"))
                            {
                                var timestamp = DateTime.Now;
                                SnmpPoll snmpPoll = new SnmpPoll(ipAddress, value.Oid.ToString(),
                                    value_string, hostname,
                                    new LocalTime(timestamp.Hour, timestamp.Minute, timestamp.Second,
                                        timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                                    new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), baseName);
                                answerSnmpPolls.Add(snmpPoll);
                            }
                        }
                    }
                    
                    else
                    {
                        Console.WriteLine($"OID {baseOid} not found or instance doesn't exist.");
                    }
                }
            }

            target.Close();
            return answerSnmpPolls;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: " + ex.Message);
            return null;
        }
    }
    public static string RemoveLastTwoIfEndsWithZero(string input)
    {
        if (input.EndsWith("0") && input.Length >= 2)
        {
            return input.Substring(0, input.Length - 2);
        }
        return input; 
    }
    
   

}

public class SnmpPollRequest
{
    public Dictionary<string, string> Oids { get; set; }
    public string IpAddress { get; set; }
    public string Hostname { get; set; }

    public string User { get; set; }
    public string AuthPass { get; set; }
    public string PrivPass { get; set; }
    public int Port { get; set; }
    public AuthenticationDigests AuthDigest { get; set; }
    public PrivacyProtocols PrivProtocol { get; set; }
    public string Name { get; set; }
    public int Id { get; set; }
    public string Authentication { get; set; }
    public string Encryption { get; set; }


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

    public SnmpPollRequest()
    {
        Oids = new Dictionary<string, string>(); // damit man kein null reference fehler bekommt
    }

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

public class SnmpPoll
{
    public string IpAddress { get; set; }
    public string Oid { get; set; }
    public string OidValue { get; set; }

    public string Hostname { get; set; }
    public string Name { get; set; }
    public LocalTime Time { get; set; }

    public LocalDate Date { get; set; }


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


    public override string ToString()
    {
        return $"SNMP Poll [IP Address: {IpAddress}, OID: {Oid}, OID Value: {OidValue}, " +
               $"Hostname: {Hostname}, Time: {Time}, Date: {Date}, Name: {Name}]";
    }
}

public enum AuthDig
{
    SHA1,
    MD5
}

public enum PrivProt
{
    AES128,
    DES
}

public class SnmpOid
{
    public string oid { get; set; }
    public string name { get; set; }
}

public class SnmpDevice
{
    public string ip { get; set; }
    public string hostname { get; set; }
    public List<SnmpOid> oids { get; set; }
    public string user { get; set; }
    public string authentication { get; set; }
    public string encryption { get; set; }
    public string authpass { get; set; }
    public string privpass { get; set; }
    public int port { get; set; }
    public string Name { get; set; }
    public int Id { get; set; }
}