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
    private readonly IDatabaseManager _databaseManager;
    
    public SnmpCustomReceiver (IDatabaseManager databaseManager)
    {
        _databaseManager = databaseManager;
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
            snmpRequest.PrivPass, snmpRequest.AuthDigest, snmpRequest.PrivProtocol, snmpRequest.Port, snmpRequest.Hostname);
    }

    public static List<SnmpPoll> PollSnmpV3(List <string> oids, string ipAddress,string user,  string authPass, string privPass, AuthenticationDigests authenticationDigests, PrivacyProtocols privacyProtocols, int port, string hostname)
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
                Dictionary<string, string> answer = new  Dictionary<string, string>();
                List<SnmpPoll> answerSnmpPolls = new List<SnmpPoll>();
                foreach (var value in values)
                {
                    string name = "temp";
                    SnmpPoll snmpPoll = new SnmpPoll(ipAddress, value.Oid.ToString(), value.Value.ToString(),
                        hostname, DateTime.Now, name);
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
    
    public Dictionary<string, Type> GetSnmpPollColumn()
    {
        return new Dictionary<string, Type>
        {
            { "deviceIP", typeof(string) },
            { "hostname", typeof(string) },
            { "devicePort", typeof(int) },
            { "oid", typeof(string) },
            { "oidValue", typeof(string) },
            { "timestamp", typeof(DateTime) },
            { "UUID", typeof(Guid)} 
        };
    }
    
    public Dictionary<string, object> MapSnmpPollDataToData(SnmpPoll snmp)
    {
        return new Dictionary<string, object>
        {
            { "deviceIP", snmp.IpAddress },
            { "hostname", snmp.Hostname },
            { "oid", snmp.Oid },
            { "oidValue", snmp.OidValue },
            { "timestamp", snmp.Timestamp },
            { "UUID", Guid.NewGuid()}  
        };
    }
    
    public async Task InsertSnmpPollDataAsync(List<SnmpPoll> snmpDatas, string table, Dictionary<string, Type> columns)
    {

        foreach (var snmpData in snmpDatas)
        {
            var data = MapSnmpPollDataToData(snmpData);

            foreach (var value in data)
            {
                Console.WriteLine(value);
            }
            
            try
            {
                await _databaseManager.InsertData(table, columns, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to insert data");
            }
        }
    }

   


}

public class SnmpPollRequest
{
    public List<string> Oids { get; set; }
    public string IpAddress { get; set; }
    public string Hostname { get; set; }

    public string User { get; set; }
    public string AuthPass { get; set; }
    public string PrivPass { get; set; }
    public int Port { get; set; }
    public AuthenticationDigests AuthDigest { get; set; }
    public PrivacyProtocols PrivProtocol { get; set; }
    public string Name { get; set; }


    public SnmpPollRequest(List<string> oids, string ipAddress, string user, string authPass, string privPass, 
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
