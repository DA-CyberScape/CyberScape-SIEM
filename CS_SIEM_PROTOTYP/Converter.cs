using SnmpSharpNet;

namespace CS_SIEM_PROTOTYP;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

/// <summary>
/// The Converter class provides methods to convert JSON data to various configurations
/// such as SNMP Poll Requests, Netflow Configurations, PRTG Configurations, SNMP Trap Configurations,
/// and Syslog Configurations.
/// </summary>
public class Converter
{
    /// <summary>
    /// Converts a list of dictionaries representing SNMP devices to a list of SnmpPollRequest objects.
    /// </summary>
    /// <param name="dictSnmp">A list of dictionaries containing SNMP device information.</param>
    /// <returns>A list of SnmpPollRequest objects populated with the converted data.</returns>
    public static List<SnmpPollRequest> ConvertJsontoSnmpPollRequest(List<Dictionary<string, object>> dictSnmp)
    {
        var jsonSnmp = JsonConvert.SerializeObject(dictSnmp);
        List<SnmpDevice> devices = JsonConvert.DeserializeObject<List<SnmpDevice>>(jsonSnmp);
        List<SnmpPollRequest> pollRequests = new List<SnmpPollRequest>();

        foreach (var device in devices)
        {
            var pollRequest = new SnmpPollRequest
            {
                IpAddress = device.ip,
                Hostname = device.hostname,
                Oids = new Dictionary<string, string>(),
                User = device.user,
                AuthPass = device.authpass,
                PrivPass = device.privpass,
                Port = device.port,
                AuthDigest = (device.authentication == "SHA1") ? AuthenticationDigests.SHA1 : AuthenticationDigests.MD5,
                PrivProtocol = (device.encryption.ToLower() == "aes 128") ? PrivacyProtocols.AES128 : PrivacyProtocols.DES,
                Name = device.Name,
                Id = device.Id,
                Authentication = device.authentication,
                Encryption = device.encryption
            };

            // convert oids
            foreach (var oid in device.oids)
            {
                if (!pollRequest.Oids.ContainsKey(oid.oid))
                {
                    pollRequest.Oids.Add(oid.oid, oid.name);
                }
            }
            pollRequests.Add(pollRequest);
        }


        return pollRequests;
    }
    /// <summary>
    /// Converts a list of dictionaries representing NetFlow configurations to a list of NfConfig objects.
    /// </summary>
    /// <param name="dictNetflow">A list of dictionaries containing NetFlow configuration information.</param>
    /// <returns>A list of NfConfig objects populated with the converted data.</returns>
    public static List<NfConfig> convertJsontoNetflowDict(List<Dictionary<string, object>> dictNetflow)
    {
        var jsonNetflow = JsonConvert.SerializeObject(dictNetflow);
        List<NfConfig> configList = JsonConvert.DeserializeObject<List<NfConfig>>(jsonNetflow);

        return configList;
    }
    /// <summary>
    /// Converts a list of dictionaries representing PRTG configurations to a list of PrtgConfig objects.
    /// </summary>
    /// <param name="dictPRTG">A list of dictionaries containing PRTG configuration information.</param>
    /// <returns>A list of PrtgConfig objects populated with the converted data.</returns>
    public static List<PrtgConfig> convertJsontoPRTG(List<Dictionary<string, object>> dictPRTG)
    {
        var jsonPrtg = JsonConvert.SerializeObject(dictPRTG);
        List<PrtgConfig> configList = JsonConvert.DeserializeObject<List<PrtgConfig>>(jsonPrtg);

        return configList;
    }
    /// <summary>
    /// Converts a list of dictionaries representing SNMP trap configurations to a list of SnmpTrapConfig objects.
    /// </summary>
    /// <param name="dictSNMPTrap">A list of dictionaries containing SNMP trap configuration information.</param>
    /// <returns>A list of SnmpTrapConfig objects populated with the converted data.</returns>
    public static List<SnmpTrapConfig> convertJsontoSNMPTrap(List<Dictionary<string, object>> dictSNMPTrap)
    {
        var jsonTrap = JsonConvert.SerializeObject(dictSNMPTrap);
        List<SnmpTrapConfig> configList = JsonConvert.DeserializeObject<List<SnmpTrapConfig>>(jsonTrap);

        return configList;
    }
    /// <summary>
    /// Converts a list of dictionaries representing Syslog configurations to a list of SyslogConfig objects.
    /// </summary>
    /// <param name="dictSyslog">A list of dictionaries containing Syslog configuration information.</param>
    /// <returns>A list of SyslogConfig objects populated with the converted data.</returns>
    public static List<SyslogConfig> ConvertJsontoSyslogConfigs(List<Dictionary<string, object>> dictSyslog)
    {
        var jsonSyslog = JsonConvert.SerializeObject(dictSyslog);
        List<SyslogConfig> configList = JsonConvert.DeserializeObject<List<SyslogConfig>>(jsonSyslog);
        return configList;
    }
}