using System.Net;
using Cassandra;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace CS_SIEM_PROTOTYP;

public class SnmpPoller
{
    public static List<SnmpPoll> WalkSnmpV3(string oid, string ipAddress, string user,
        string authPass, string privPass, int port, string hostname, string authentication, string encryption,
        Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        var userOctetString = new OctetString(user);
        var auth = GetAuthenticationProvider(authentication, authPass);
        var priv = GetPrivacyProvider(encryption, privPass, auth);
        var target = new IPEndPoint(IPAddress.Parse(ipAddress), port);
        var rootOid = new ObjectIdentifier(oid);
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetBulkRequestPdu);
        var report = discovery.GetResponse(10000, target);
        var answerSnmpPolls = new List<SnmpPoll>();
        try
        {
            Console.WriteLine("Starting SNMPv3 Walk...");
            var answer = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V3,
                target,
                userOctetString,
                OctetString.Empty,
                rootOid,
                answer,
                60000,
                10,
                WalkMode.WithinSubtree,
                priv,
                report);
            foreach (var variable in answer)
            {
                var queriedOid = variable.Id.ToString();
                var queriedValue = variable.Data.ToString();
                var timestamp = DateTime.Now;
                var snmpPoll = new SnmpPoll(ipAddress, queriedOid, queriedValue, hostname, new LocalTime(timestamp.Hour,
                        timestamp.Minute,
                        timestamp.Second,
                        timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                    new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), "testing chicken");
                answerSnmpPolls.Add(snmpPoll);
                Console.WriteLine(snmpPoll);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during SNMPv3 Walk: {ex.Message}");
        }

        return answerSnmpPolls;
    }

    public static List<SnmpPoll> PollSnmpV3(string oid, string ipAddress, string user,
        string authPass, string privPass, int port, string hostname, string authentication, string encryption,
        Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        var userOctetString = new OctetString(user);
        var auth = GetAuthenticationProvider(authentication, authPass);
        var priv = GetPrivacyProvider(encryption, privPass, auth);
        var target = new IPEndPoint(IPAddress.Parse(ipAddress), port);
        var rootOid = new ObjectIdentifier(oid);
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        var report = discovery.GetResponse(10000, target);
        var oidsList = new List<Variable> { new(new ObjectIdentifier(oid)) };

        var answerSnmpPolls = new List<SnmpPoll>();
        try
        {
            var request = new GetRequestMessage(
                VersionCode.V3,
                Messenger.NextMessageId,
                Messenger.NextRequestId,
                userOctetString,
                oidsList,
                priv,
                Messenger.MaxMessageSize,
                report);

            var response = request.GetResponse(
                10000,
                target);

            foreach (var variable in response.Pdu().Variables)
            {
                var queriedOid = variable.Id.ToString();
                var queriedValue = variable.Data.ToString();
                var timestamp = DateTime.Now;
                var snmpPoll = new SnmpPoll(ipAddress, queriedOid, queriedValue, hostname, new LocalTime(timestamp.Hour,
                        timestamp.Minute,
                        timestamp.Second,
                        timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                    new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), "testing chicken");
                answerSnmpPolls.Add(snmpPoll);
                Console.WriteLine(snmpPoll);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during SNMPv3 Walk: {ex.Message}");
        }

        return answerSnmpPolls;
    }


    private static IAuthenticationProvider GetAuthenticationProvider(string authentication, string authPass)
    {
        switch (authentication.ToUpper())
        {
            case "MD5":
                return new MD5AuthenticationProvider(new OctetString(authPass));
            case "SHA1":
                return new SHA1AuthenticationProvider(new OctetString(authPass));
            case "SHA256":
                return new SHA256AuthenticationProvider(new OctetString(authPass));
            case "SHA384":
                return new SHA384AuthenticationProvider(new OctetString(authPass));
            case "SHA512":
                return new SHA512AuthenticationProvider(new OctetString(authPass));
            default:
                throw new ArgumentException("Unsupported authentication type");
        }
    }

    private static IPrivacyProvider GetPrivacyProvider(string encryption, string privPass, IAuthenticationProvider auth)
    {
        switch (encryption.ToUpper())
        {
            case "DES":
                return new DESPrivacyProvider(new OctetString(privPass), auth);
            case "AES":
                return new AESPrivacyProvider(new OctetString(privPass), auth);
            case "AES128":
                return new AESPrivacyProvider(new OctetString(privPass), auth);
            case "AES192":
                return new AES192PrivacyProvider(new OctetString(privPass), auth);
            case "AES256":
                return new AES256PrivacyProvider(new OctetString(privPass), auth);
            default:
                throw new ArgumentException("Unsupported encryption type");
        }
    }
}