// See https://aka.ms/new-console-template for more information

#define DISABLE_DATABASE_TEST
#define DISABLE_SNMP_TEST

using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Principal;
using System.Text.Json.Nodes;
using CS_DatabaseManager;
using DotNetEnv;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PacketDotNet.Utils;
using SnmpSharpNet;

namespace CS_SIEM_PROTOTYP;

public static class Program
{
    private static short _counter;

    

    public static JArray ParseJson(string jsonPath)
    {
        string jsonText = File.ReadAllText(jsonPath);
        
        JArray jsonResult = JArray.Parse(jsonText);
    
        return jsonResult; 
    }
    
    static void PrintDictionary<T>(T dict)
    {
        Console.WriteLine(JsonConvert.SerializeObject(dict, Formatting.Indented));
        Console.WriteLine("------------------------------------");
    }

    



    public static async Task Main(string[] args)
    {
        string absolutePath = @"C:\Users\apexl\Desktop\CyberScape-SIEM\CS_SIEM_PROTOTYP\example_API.json";
        var jsonArray = ParseJson(absolutePath);
        // Console.WriteLine(test[0]);
        // Console.WriteLine(test.Count);
        var snmpPollsDict = new List<Dictionary<string, object>>();
        var netflowReceiverDict = new List<Dictionary<string, object>>();
        var prtgReceiverDict = new List<Dictionary<string, object>>();
        var snmpTrapReceiverDict = new List<Dictionary<string, object>>();
        var syslogDict = new List<Dictionary<string, object>>();
        foreach (JObject item in jsonArray)
        {
            if (item["snmpPolls"] != null)
            {
                snmpPollsDict = item["snmpPolls"].ToObject<List<Dictionary<string, object>>>();
                PrintDictionary(snmpPollsDict);
            }

            if (item["netflowReceiver"] != null)
            {
                netflowReceiverDict = item["netflowReceiver"].ToObject<List<Dictionary<string, object>>>();
                PrintDictionary(netflowReceiverDict);
            }

            if (item["PRTGReceiver"] != null)
            {
                prtgReceiverDict = item["PRTGReceiver"].ToObject<List<Dictionary<string, object>>>();
                PrintDictionary(prtgReceiverDict);
            }

            if (item["snmpTrapReceiver"] != null)
            {
                snmpTrapReceiverDict = item["snmpTrapReceiver"].ToObject<List<Dictionary<string, object>>>();
                PrintDictionary(snmpTrapReceiverDict);
            }

            if (item["Syslog"] != null)
            {
                syslogDict = item["Syslog"].ToObject<List<Dictionary<string, object>>>();
                PrintDictionary(syslogDict);
            }

            if (item["ScyllaDB"] != null)
            {
                var scyllaDbDict = item["ScyllaDB"].ToObject<Dictionary<string, object>>();
                PrintDictionary(scyllaDbDict);
            }
        }

        var tempSNMP = Converter.convertJsontoSNMPPollRequest(snmpPollsDict);

        foreach (var element in tempSNMP)
        {
            
            Console.WriteLine(element);
        }

        var tempNetflow = Converter.convertJsontoNetflowDict(netflowReceiverDict);
        foreach (var element in tempNetflow)
        {
            Console.WriteLine(element);
            
        }
        var tempPRTG = Converter.convertJsontoPRTG(prtgReceiverDict);
        foreach (var element in tempPRTG)
        {
            Console.WriteLine(element);
            
        }
        var tempSNMPTrap = Converter.convertJsontoSNMPTrap(snmpTrapReceiverDict);
        foreach (var element in tempSNMPTrap)
        {
            Console.WriteLine(element);
            
        }
        var tempSyslogp = Converter.ConvertJsontoSyslogConfigs(syslogDict);
        foreach (var element in tempSyslogp)
        {
            Console.WriteLine(element);
            
        }
        
        SyslogReceiver.TestProcessSyslogMessage();
        
        /*
        
        var oidDictionary = new Dictionary<string, string>
        {
            { "1.3.6.1.4.1.9.2.1.56.0", "CPU Load" },
            { "1.3.6.1.4.1.9.2.1.8.0", "Memory Usage" },
            { "1.3.6.1.2.1.1.3.0", "Uptime" },
            { "1.3.6.1.2.1.6.9.0", "TCP Connections" }
        };
        
        List<string> oidList = oidDictionary.Keys.ToList();
        List<string> valueList = oidDictionary.Values.ToList();
        Console.WriteLine(string.Join(", ", oidList));
        Console.WriteLine(string.Join(", ", valueList));
        Console.WriteLine(oidDictionary["1.3.6.1.4.1.9.2.1.56.0"]);
        */
        /*
        

        List<string> oids = new List<string>
                {
                    "1.3.6.1.4.1.9.2.1.56.0", // cpu load
                    "1.3.6.1.4.1.9.2.1.8.0", // avail ra
                    "1.3.6.1.2.1.1.5.0", //name
                    "1.3.6.1.2.1.1.3.0", // uptime
                    "1.3.6.1.2.1.2.2.1.2",
                    

                };
        AuthenticationDigests authenticationDigests = AuthenticationDigests.SHA1;
        PrivacyProtocols privacyProtocols = PrivacyProtocols.AES128;
        string ip = "192.168.10.20";
        string user = "MY-USER";
        string authpass = "MyAuthPass";
        string privpass = "MyPrivPass";
        int port = 161;
        string hostname = "Switch";
       
        


        SnmpPollRequest snmpPollRequest = new SnmpPollRequest(oids, ip, user, authpass, privpass, authenticationDigests, privacyProtocols, port, hostname);


        var responses = SnmpCustomReceiver.PollSnmpV3(snmpPollRequest);
        
        foreach (var response in responses)
        {
            Console.WriteLine(response);
            Console.WriteLine("-----------------------------");
        }
        */
        
        
        
        /*
        

        // Syslog THREAD
        Thread syslogThread = new Thread(() => startSyslogReceiver(514));
        syslogThread.Start();*/
        
        
        
        /*
        Console.WriteLine("Hello World");
        Console.WriteLine("-----------------------------");
        
        string nfdump_files = "/var/cache/nfdump";
        string nfdump_bin = "/bin/nfdump";
        string[] netflowPaths = NetflowReceiver.GetFilePaths(nfdump_files);




        foreach (string nfpath in netflowPaths)
        {
            Console.WriteLine(nfpath + " OUPUT: ");
            List<string> lines = NetflowReceiver.ProcessCapturedFile(nfpath, nfdump_bin);
            List<NetFlowData> nfDatas = NetflowReceiver.ParseNetFlowData(lines);
            foreach (var nfdata in nfDatas)
            {
                Console.WriteLine(nfdata);

            }

        }
        
        
        List<string> oids = new List<string>
        {
            "1.3.6.1.4.1.9.2.1.56.0", // cpu load
            "1.3.6.1.4.1.9.2.1.8.0", // avail ram
            "1.3.6.1.2.1.6.9.0", // TCP Sessions
            "1.3.6.1.2.1.1.3.0", // uptime
            "1.3.6.1.4.1.9.2.1.57.0", // cpu load 60sec
            "1.3.6.1.2.1.2.2.1.2"
            
        };

        
        string community = "cssiemtest"; // Replace with your SNMP community string
        string ipAddress = "192.168.10.20"; // Replace with the IP address of your Cisco router


       

        Dictionary<string, string> responses = SnmpCustomReceiver.PollMultipleOids(oids, ipAddress, community);
        Console.WriteLine("Cisco Router Metrics:");
        
        
        foreach (var response in responses)
        {
            Console.WriteLine($"{ipAddress}: {response.Value}");
        }
        */
        /*

        var services = new ServiceCollection();

        //to change the cluster/hosts go to DbHostProvider.cs
        services.AddSingleton<DbHostProvider>();
        // ScyllaDatabaseManager is the actual "Wrapper" for the Scylla Cluster
        services.AddSingleton<IDatabaseManager, ScyllaDatabaseManager>();
        // DummyDatabaseManager is a Dummy implementation of the IDatabaseManager Interface
//        services.AddSingleton<IDatabaseManager, DummyDatabaseManager>();
        services.AddSingleton<PrtgReceiver>();
        services.AddSingleton<NetflowReceiver>();

        var serviceProvider = services.BuildServiceProvider();

        var db = serviceProvider.GetService<IDatabaseManager>()!;
        Console.WriteLine(db.GetType());
        db.SetKeySpace("Test_Keyspace");
        
        Console.WriteLine("IT WORKS");
        // API THREAD
        Thread apiThread = new Thread(() => StartApi(db));
        apiThread.Start();
        */
        




        // PRTG/SNMP THREAD
        /*
        string url = "http://192.168.10.3";
        Thread prtgThread = new Thread(() => StartPrtg(db, serviceProvider, url));
        prtgThread.Start();
        */
        // PRTG/SNMP THREAD

        
        // Netflow THREAD

        // StartNetflow(db, serviceProvider);

//        Thread nfThread = new Thread(() => StartNetflow(db, serviceProvider));
//        nfThread.Start();

        // Netflow THREAD
        
        
        
 

        #region SNMP

#if !DISABLE_SNMP_TEST

        //---------------------------------

        var results = await db.SelectData("SNMP");

        foreach (var row in results)
        {
            Console.WriteLine(string.Join(", ", row.Select(kv => $"{kv.Key}: {kv.Value}")));
        }
#endif

        #endregion


        #region DATABASE_TEST

#if !DISABLE_DATABASE_TEST
        //check if scylla is running locally
        // if (false)
        // {
        //     const string serviceName = "scylla-server.service";
        //     const int checkInterval = 5000;
        //
        //     while (!IsServiceRunning(serviceName))
        //     {
        //         Console.WriteLine($"{serviceName} is not running. Waiting...");
        //         Thread.Sleep(checkInterval);
        //     }
        //
        //     Console.WriteLine($"{serviceName} is running. Proceeding with application start.");
        // }

//        db.PrintKeyspaces();

        var columns = new Dictionary<string, Type>
        {
            { "IPv4", typeof(IPAddress) },
            { "Name", typeof(string) },
            { "Timestamp", typeof(DateTime) },
        };

        var data = new Dictionary<string, object>
        {
            { "IPv4", IPAddress.Parse("192.168.1.1") },
            { "Name", "Test Entry" },
            { "Timestamp", DateTime.UtcNow }
        };

        await db.CreateTable("test_table", columns, "UUID");

        await db.InsertData("test_table", columns, data);

        await GenerateDummyData(db);

        var resultDict = await db.SelectData("test_table", "");

        foreach (var res in resultDict)
        {
            foreach (var keyValuePair in res)
            {
                Console.WriteLine(keyValuePair.Key);
                Console.WriteLine(keyValuePair.Value);
            }
        }

        // await GenerateDummyData(db);

#endif

        #endregion

//        await Task.Run(Run);
    }


    private static async Task GenerateDummyData(IDatabaseManager db)
    {
        var columns = new Dictionary<string, Type>
        {
            { "IPv4", typeof(IPAddress) },
            { "Name", typeof(string) },
            { "Timestamp", typeof(DateTime) },
        };

        var dataBatch = new List<Dictionary<string, object>>();

        var random = new Random();

        for (long i = 0 + _counter; i < 100 + _counter; i++)
        {
            var data = new Dictionary<string, object>
            {
                { "IPv4", IPAddress.Parse($"192.168.1.{random.Next(1, 255)}") },
                { "Name", $"Entry {i + 1}" },
                { "Timestamp", DateTime.UtcNow.AddMinutes(-random.Next(0, 1000)) }
            };

            dataBatch.Add(data);
            // Thread.Sleep(100);
        }

        _counter += 100;
        // Console.WriteLine(dataBatch.Count);
        await db.InsertBatchedData("test_table", columns, dataBatch);

        Console.WriteLine("Generated all Data");
    }


    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            Process process = new Process();
            process.StartInfo.FileName = "systemctl";
            process.StartInfo.Arguments = $"is-active {serviceName}";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return output.Trim().Equals("active", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking service status: {ex.Message}");
            return false;
        }
    }

    private static void Run()
    {
        while (!(Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.X))
        {
            Console.WriteLine("Press 'x' to stop!");
            Thread.Sleep(5000);
        }
    }
}