using SnmpSharpNet;

namespace CS_SIEM_PROTOTYP;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class Converter
{
    public static List<SnmpPollRequest> convertJsontoSNMPPollRequest(List<Dictionary<string, object>> dictSNMP)
    {
        var jsonSNMP = JsonConvert.SerializeObject(dictSNMP);
        List<SnmpDevice> devices = JsonConvert.DeserializeObject<List<SnmpDevice>>(jsonSNMP);
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
                PrivProtocol = (device.encryption == "aes 128") ? PrivacyProtocols.AES128 : PrivacyProtocols.DES,
                Name = device.Name,
                Id = device.Id
            };

            // convert oids
            foreach (var oid in device.oids)
            {
                pollRequest.Oids.Add(oid.oid, oid.name);
            }

            pollRequests.Add(pollRequest);
        }


        return pollRequests;
    }

    public static List<NfConfig> convertJsontoNetflowDict(List<Dictionary<string, object>> dictNetflow)
    {
        var jsonNetflow = JsonConvert.SerializeObject(dictNetflow);
        List<NfConfig> configList = JsonConvert.DeserializeObject<List<NfConfig>>(jsonNetflow);

        return configList;
    }

    public static List<PrtgConfig> convertJsontoPRTG(List<Dictionary<string, object>> dictPRTG)
    {
        var jsonPrtg = JsonConvert.SerializeObject(dictPRTG);
        List<PrtgConfig> configList = JsonConvert.DeserializeObject<List<PrtgConfig>>(jsonPrtg);

        return configList;
    }

    public static List<SnmpTrapConfig> convertJsontoSNMPTrap(List<Dictionary<string, object>> dictSNMPTrap)
    {
        var jsonTrap = JsonConvert.SerializeObject(dictSNMPTrap);
        List<SnmpTrapConfig> configList = JsonConvert.DeserializeObject<List<SnmpTrapConfig>>(jsonTrap);

        return configList;
    }

    public static List<SyslogConfig> ConvertJsontoSyslogConfigs(List<Dictionary<string, object>> dictSyslog)
    {
        var jsonSyslog = JsonConvert.SerializeObject(dictSyslog);
        List<SyslogConfig> configList = JsonConvert.DeserializeObject<List<SyslogConfig>>(jsonSyslog);
        return configList;
    }
}