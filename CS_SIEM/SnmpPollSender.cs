using System.Net;
using Cassandra;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace CS_SIEM;

/// <summary>
/// Provides functionality to send SNMP polls using SNMPv3.
/// </summary>
public class SnmpPollSender
{
    /// <summary>
    /// Performs an SNMPv3 bulk walk (GETBULK request) to retrieve multiple OID values from a device.
    /// </summary>
    /// <param name="baseOid">The base OID to start the walk from.</param>
    /// <param name="ipAddress">The IP address of the SNMP device.</param>
    /// <param name="user">The SNMPv3 username.</param>
    /// <param name="authPass">The SNMPv3 authentication password.</param>
    /// <param name="privPass">The SNMPv3 privacy password.</param>
    /// <param name="port">The port number for the SNMP request.</param>
    /// <param name="hostname">The hostname of the SNMP device.</param>
    /// <param name="authentication">The authentication type (e.g., MD5, SHA1).</param>
    /// <param name="encryption">The encryption type (e.g., DES, AES).</param>
    /// <param name="baseName">The base name for the OID if no specific name is found.</param>
    /// <param name="oidDictionary">A dictionary mapping OIDs to their corresponding names and descriptions.</param>
    /// <returns>A list of <see cref="SnmpPoll"/> objects containing the polled data.</returns>
    public static List<SnmpPoll> WalkSnmpV3(string baseOid, string ipAddress, string user,
        string authPass, string privPass, int port, string hostname, string authentication, string encryption,
        string baseName,
        Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        
        var userOctetString = new OctetString(user);
        var auth = GetAuthenticationProvider(authentication, authPass);
        var priv = GetPrivacyProvider(encryption, privPass, auth);
        var target = new IPEndPoint(IPAddress.Parse(ipAddress), port);
        var rootOid = new ObjectIdentifier(baseOid);
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetBulkRequestPdu);
        var report = discovery.GetResponse(10000, target);
        var answerSnmpPolls = new List<SnmpPoll>();
        var rootName = "";
        {
            // neuer scope damit wert1 und wert2 nicht spaeter nerven
            if (oidDictionary.TryGetValue(baseOid, out var wert1))
            {
                // suche nach rootName
                rootName = wert1.ObjectName;
            }
            else if (oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(baseOid), out var wert2))
            {
                // suche nach rootName ohne .0 am Ende
                rootName = wert2.ObjectName;
            }
            
        }
        
        try
        {
            var answer = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V3,
                target,
                userOctetString,
                OctetString.Empty,
                rootOid,
                answer,
                1000,
                10,
                WalkMode.WithinSubtree,
                priv,
                report);
            foreach (var variable in answer)
            {
                var queriedOid = variable.Id.ToString();
                var queriedValue = variable.Data.ToString();
                var timestamp = DateTime.Now;
                var modifiedName = rootName;
                if (oidDictionary.TryGetValue(queriedOid, out var wert1))
                {
                    // suche nach spezifischen Namen
                    modifiedName = wert1.ObjectName;
                }
                else if (oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(queriedOid), out var wert2))
                {
                    // suche nach spezifischen Namen ohne .0 am ende
                    modifiedName = wert2.ObjectName;
                }
                
                if (string.IsNullOrEmpty(modifiedName))
                {
                    //1.3.6.1.4.1.12356.101.7.2 (base oid) difference 1.3.6.1.4.1.12356.101.7.2.1.1.1  (specific oid)= 1.1.1
                    // wenn er keinen namen findet fuer seine baseoid und specific oid
                    modifiedName = baseName + GetDifference(queriedOid, baseOid);
                }
                else if (modifiedName == rootName)
                {
                    // wenn er keinen spezifischen Namen finden kann fuer seine specific oid
                    modifiedName = rootName + GetDifference(queriedOid, baseOid);
                }
                var snmpPoll = new SnmpPoll(ipAddress, queriedOid, queriedValue, hostname, new LocalTime(timestamp.Hour,
                        timestamp.Minute,
                        timestamp.Second,
                        timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                    new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), modifiedName);
                answerSnmpPolls.Add(snmpPoll);
                // Console.WriteLine(snmpPoll);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during SNMPv3 Walk: {ex.Message}");
        }finally
        {
            discovery = null;
            auth = null;
            priv = null;
            userOctetString = null;
        }

        return answerSnmpPolls;
    }

    /// <summary>
    /// Performs an SNMPv3 GET request to retrieve a single OID value from a device.
    /// </summary>
    /// <param name="baseOid">The OID to retrieve.</param>
    /// <param name="ipAddress">The IP address of the SNMP device.</param>
    /// <param name="user">The SNMPv3 username.</param>
    /// <param name="authPass">The SNMPv3 authentication password.</param>
    /// <param name="privPass">The SNMPv3 privacy password.</param>
    /// <param name="port">The port number for the SNMP request.</param>
    /// <param name="hostname">The hostname of the SNMP device.</param>
    /// <param name="authentication">The authentication type (e.g., MD5, SHA1).</param>
    /// <param name="encryption">The encryption type (e.g., DES, AES).</param>
    /// <param name="baseName">The base name for the OID if no specific name is found.</param>
    /// <param name="oidDictionary">A dictionary mapping OIDs to their corresponding names and descriptions.</param>
    /// <returns>A list of <see cref="SnmpPoll"/> objects containing the polled data.</returns>
    public static List<SnmpPoll> GetSnmpV3(string baseOid, string ipAddress, string user,
        string authPass, string privPass, int port, string hostname, string authentication, string encryption,
        string baseName,
        Dictionary<string, (string ObjectName, string Description)> oidDictionary)
    {
        var userOctetString = new OctetString(user);
        var auth = GetAuthenticationProvider(authentication, authPass);
        var priv = GetPrivacyProvider(encryption, privPass, auth);
        var target = new IPEndPoint(IPAddress.Parse(ipAddress), port);
        var rootOid = new ObjectIdentifier(baseOid);
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        var report = discovery.GetResponse(10000, target);
        var oidsList = new List<Variable> { new(new ObjectIdentifier(baseOid)) };
        var rootName = "";

        {
            // neuer scope damit wert1 und wert2 nicht spaeter nerven
            if (oidDictionary.TryGetValue(baseOid, out var wert1))
            {
                // suche nach rootName
                rootName = wert1.ObjectName;
            }
            else if (oidDictionary.TryGetValue(RemoveLastTwoIfEndsWithZero(baseOid), out var wert2))
            {
                // suche nach rootName ohne .0 am Ende
                rootName = wert2.ObjectName;
            }
            else
            {
                rootName = baseName;
            }

        }
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
                
              
                // Console.WriteLine($"4ObjectName: {modifiedName} OID: {oidValue}");

                var timestamp = DateTime.Now;
                var snmpPoll = new SnmpPoll(ipAddress, queriedOid, queriedValue, hostname, new LocalTime(timestamp.Hour,
                        timestamp.Minute,
                        timestamp.Second,
                        timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000),
                    new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day), rootName);
                answerSnmpPolls.Add(snmpPoll);
                // Console.WriteLine(snmpPoll);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during SNMPv3 Walk: {ex.Message}");
        }finally
        {
            discovery = null;
            auth = null;
            priv = null;
            userOctetString = null;
        }

        return answerSnmpPolls;
    }


    /// <summary>
    /// Gets the appropriate authentication provider based on the specified authentication type.
    /// </summary>
    /// <param name="authentication">The authentication type (e.g., MD5, SHA1).</param>
    /// <param name="authPass">The authentication password.</param>
    /// <returns>An instance of <see cref="IAuthenticationProvider"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the authentication type is unsupported.</exception>
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

    /// <summary>
    /// Gets the appropriate privacy provider based on the specified encryption type.
    /// </summary>
    /// <param name="encryption">The encryption type (e.g., DES, AES).</param>
    /// <param name="privPass">The privacy password.</param>
    /// <param name="auth">The authentication provider.</param>
    /// <returns>An instance of <see cref="IPrivacyProvider"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the encryption type is unsupported.</exception>
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

    /// <summary>
    /// Removes the last two characters from a string if it ends with "0".
    /// Used to retrieve the OID Name for a specific OID during snmp walks or snmp gets
    /// </summary>
    /// <param name="input">The input string.</param>
    /// <returns>The modified string.</returns>
    private static string RemoveLastTwoIfEndsWithZero(string input)
    {
        if (input.EndsWith("0") && input.Length >= 2) return input.Substring(0, input.Length - 2);
        return input;
    }

    /// <summary>
    /// Gets the difference between two OID strings.
    /// Used to get append the difference to the OID name if no specific OID name has been found in the OID dictionary
    /// </summary>
    /// <param name="longerStr">The longer OID string.</param>
    /// <param name="shorterStr">The shorter OID string.</param>
    /// <returns>The substring difference between the two OIDs.</returns>
    private static string GetDifference(string longerStr, string shorterStr)
    {
        return longerStr.Substring(shorterStr.Length);
    }
}