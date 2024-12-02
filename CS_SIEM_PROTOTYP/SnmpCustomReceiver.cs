namespace CS_SIEM_PROTOTYP;

using CS_DatabaseManager;
using System;
using SnmpSharpNet;

//https://github.com/rqx110/SnmpSharpNet/wiki
public class SnmpCustomReceiver : IDataReceiver
{
    public void ReceiveData()
    {
        throw new NotImplementedException();
    }


    // snmp-server group MY-GROUP v3 priv
    // snmp-server user MY-USER MY-GROUP v3 auth sha MyAuthPass priv aes 128 MyPrivPass
    // snmp-server enable traps

    public static string PollSnmp(string oid, string ipAddress, string community)
    {
        try
        {
            // Ziel mit port 161, 
            UdpTarget target = new UdpTarget((System.Net.IPAddress)new IpAddress(ipAddress), 161, 2000, 1);

            // get request pdu
            Pdu pdu = new Pdu(PduType.Get);
            pdu.VbList.Add(oid);

            // community, version
            AgentParameters param = new AgentParameters(SnmpVersion.Ver2, new OctetString(community));

            // ausfuehren
            SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);


            target.Close();


            if (result == null)
            {
                return "Error: No response from SNMP agent.";
            }
            else if (result.Pdu.ErrorStatus != 0)
            {
                // SNMP error
                return "Error: " + result.Pdu.ErrorStatus.ToString();
            }
            else
            {
                // SNMP antwort
                return result.Pdu.VbList[0].Value.ToString();
            }
        }
        catch (Exception ex)
        {
            return "Exception: " + ex.Message;
        }
    }

    public static Dictionary<string, string> PollMultipleOids(List<string> oids, string ipAddress, string community)
    {
        Dictionary<string, string> results = new Dictionary<string, string>();

        foreach (string oid in oids)
        {
            string response = PollSnmp(oid, ipAddress, community);
            results.Add(oid, response);
        }

        return results;
    }

    public static List<SnmpPoll> PollSnmpV3(SnmpPollRequest snmpRequest)
    {
        return PollSnmpV3(snmpRequest.Oids, snmpRequest.IpAddress, snmpRequest.User, snmpRequest.AuthPass,
            snmpRequest.PrivPass, snmpRequest.AuthDigest, snmpRequest.PrivProtocol, snmpRequest.Port,
            snmpRequest.Hostname);
    }

    public static List<SnmpPoll> PollSnmpV3Temp(Dictionary<string, string> oidDict, string ipAddress, string user,
        string authPass, string privPass, AuthenticationDigests authenticationDigests,
        PrivacyProtocols privacyProtocols, int port, string hostname)
    {
        try
        {
            // Ziel mit port 161, 
            UdpTarget target = new UdpTarget((System.Net.IPAddress)new IpAddress(ipAddress), port, 2000, 1);
            SecureAgentParameters param = new SecureAgentParameters();
            if (!target.Discovery(param))
            {
                Console.WriteLine("Discovery failed. Unable to continue...");
                target.Close();
                return null;
            }

            List<string> oids = oidDict.Keys.ToList();
            foreach (var oid in oids)
            {
                Console.WriteLine(oid);
            }
            // List <string> oids_value = oidDict.Values.ToList();

            // get request pdu
            Pdu pdu = new Pdu(PduType.Get);
            foreach (var oid in oids)
            {
                pdu.VbList.Add(oid);
            }


            param.authPriv(
                user,
                authenticationDigests, authPass,
                privacyProtocols, privPass);


            // ausfuehren
            SnmpV3Packet result = (SnmpV3Packet)target.Request(pdu, param);


            target.Close();
            if (result == null)
            {
                Console.WriteLine("Error: No response from SNMP agent.");
                return null;
            }
            else if (result.Pdu.ErrorStatus != 0)
            {
                // SNMP error
                Console.WriteLine("Error: " + result.Pdu.ErrorStatus.ToString());
                return null;
            }
            else
            {
                // SNMP antwort
                var values = result.Pdu.VbList;
                Dictionary<string, string> answer = new Dictionary<string, string>();
                List<SnmpPoll> answerSnmpPolls = new List<SnmpPoll>();
                foreach (var value in values)
                {
                    // string name = "temp";
                    string oid = value.Oid.ToString();
                    SnmpPoll snmpPoll = new SnmpPoll(ipAddress, oid, value.Value.ToString(),
                        hostname, DateTime.UtcNow.AddHours(1), oidDict[oid]);
                    answerSnmpPolls.Add(snmpPoll);
                }

                return answerSnmpPolls;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: " + ex.Message);
            return null;
        }
    }
    public static List<SnmpPoll> PollSnmpV3(Dictionary<string, string> oidDict, string ipAddress, string user,
        string authPass, string privPass, AuthenticationDigests authenticationDigests,
        PrivacyProtocols privacyProtocols, int port, string hostname)
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
            foreach (var entry in oidDict)
            {
                string baseOid = entry.Key;
                string baseName = entry.Value;
    
                // Check if the OID does not end with ".0"
                if (!baseOid.EndsWith(".0"))
                {
                    // Loop to append ".x" to the base OID where x ranges from 1 to 100
                    for (int x = 1; x <= 30; x++)
                    {
                        string modifiedOid = $"{baseOid}.{x}";
                        string modifiedName = $"{baseName}.{x}";
    
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
                                    
                                    SnmpPoll snmpPoll = new SnmpPoll(ipAddress, value.Oid.ToString(),
                                                                        value_string, hostname, DateTime.UtcNow.AddHours(1), modifiedName);
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
                else
                {
                    // Directly add non-.1 OIDs
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
                                SnmpPoll snmpPoll = new SnmpPoll(ipAddress, value.Oid.ToString(),
                                    value_string, hostname, DateTime.UtcNow.AddHours(1), baseName);
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
    public DateTime Timestamp { get; set; }


    public SnmpPoll(string ipAddress, string oid, string oidValue, string hostname, DateTime timestamp, string name)
    {
        IpAddress = ipAddress;
        Oid = oid;
        OidValue = oidValue;
        Hostname = hostname;
        Timestamp = timestamp;
        Name = name;
    }


    public override string ToString()
    {
        return $"SNMP Poll [IP Address: {IpAddress}, OID: {Oid}, OID Value: {OidValue}, " +
               $"Hostname: {Hostname}, Timestamp: {Timestamp}, Name: {Name}]";
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

