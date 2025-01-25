// See https://aka.ms/new-console-template for more information

#define DISABLE_DATABASE_TEST
#define DISABLE_SNMP_TEST

using System.Diagnostics;
using System.Net;
using CS_DatabaseManager;
using static CS_SIEM_PROTOTYP.SnmpPoller;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Cassandra;

namespace CS_SIEM_PROTOTYP;

public static class Program
{
    private static short _counter;


    public static async Task Main(string[] args)
    {
        var oidDictionary = new Dictionary<string, (string ObjectName, string Description)>
        {
            { "1.3.6.1.2.1.4.20.1.4", ("SUBNETMASKS", "A description of the entity") },
            { "1.3.6.1.2.1.1.2", ("sysObjectID", "The vendor's authoritative identification of the network management subsystem") },
            { "1.3.6.1.2.1.4.20.1.3.10.40.21.151", ("SPECIFIC NAME", "The time since the network management portion of the system was last re-initialized") }
        };
        
        WalkSnmpV3("1.3.6.1.2.1.4.20.1.3", "10.0.1.254", "MY-USER", "MyAuthPass", "MyPrivPass", 161, "Fortigate",
            "SHA1", "AES", "SNETMASK", oidDictionary);


        // PollSnmpV3("1.3.6.1.4.1.12356.101.4.1.3.0", "10.0.1.254", "MY-USER", "MyAuthPass", "MyPrivPass", 161, "Fortigate",
        //     "SHA1", "AES", null);


        // SnmpV3TrapReceiver.StartReceiver();
        /*
        SyslogReceiver syslogReceiver = new SyslogReceiver(null, 514, 10);
        Task receiveTask = Task.Run(() => syslogReceiver.ReceiveSyslogData());
        Console.WriteLine("WE ARE WAITING");
        await Task.Delay(60_000);
        syslogReceiver.StopReceiver();

        await receiveTask;
        Console.WriteLine("FINISHED");*/


        // Console.WriteLine("------------------------------------------");
        // DbHostProvider dbHost = new DbHostProvider();
        //IDatabaseManager db = new ScyllaDatabaseManager(dbHost);

        //ModuleStarter moduleStarter = new ModuleStarter(db, 10);
        //var siemTask = moduleStarter.StartSIEM(@"/home/cyberscape_admin/CyberScape-SIEM/CS_SIEM_PROTOTYP/test.json");

        //Console.WriteLine("[SIMULATION] SIEM Started, waiting 60 seconds before stopping...");
        //await Task.Delay(60_000);
        //moduleStarter.StopSIEM();
        //await siemTask;
        //Console.WriteLine("[SIMULATION] SIEM has been stopped.");


        // TESTING NETFLOW AND SNMP
        /*
        NetflowScheduler netflowScheduler = new NetflowScheduler(tempNetflow, null, 10);
        netflowScheduler.StartAnalyzingAsync();

        SnmpPollScheduler snmpPollScheduler = new SnmpPollScheduler(tempSNMP, null, 10 );
        snmpPollScheduler.StartPollingAsync();

        Console.WriteLine("Waiting for 60 Seconds TILL STOP");
        await Task.Delay(60 * 1000);

        snmpPollScheduler.StopPolling();
        netflowScheduler.StopPolling();*/


        // SyslogReceiver.TestProcessSyslogMessage();


        // public static List<SnmpPoll> PollSnmpV3(Dictionary <string, string> oidDict, string ipAddress,string user,  string authPass, string privPass,
        // AuthenticationDigests authenticationDigests, PrivacyProtocols privacyProtocols, int port, string hostname)

        /*
        Console.WriteLine(tempSNMP[1].Oids);
        Console.WriteLine(tempSNMP[1].IpAddress);
        Console.WriteLine(tempSNMP[1].User);
        Console.WriteLine(tempSNMP[1].AuthPass);
        Console.WriteLine(tempSNMP[1].PrivPass);
        Console.WriteLine(tempSNMP[1].AuthDigest);
        Console.WriteLine(tempSNMP[1].PrivProtocol);
        Console.WriteLine(tempSNMP[1].Port);
        Console.WriteLine(tempSNMP[1].Hostname);

        var temp = SnmpCustomReceiver.PollSnmpV3(tempSNMP[1].Oids, tempSNMP[1].IpAddress, tempSNMP[1].User, tempSNMP[1].AuthPass, tempSNMP[1].PrivPass, tempSNMP[1].AuthDigest, tempSNMP[1].PrivProtocol, tempSNMP[1].Port, tempSNMP[1].Hostname);

        foreach (var t in temp)
        {
            Console.WriteLine(t);

        }
        */
        /*
         snmpwalk -v3 -l authPriv -u MY-USER -a SHA -A MyAuthPass -x AES -X MyPrivPass -p 161 192.168.10.20 1.3.6.1.4.1.9.2.1.56.0



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
            { "Timestamp", typeof(DateTime) }
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
            var process = new Process();
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