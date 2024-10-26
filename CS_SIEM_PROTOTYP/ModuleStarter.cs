namespace CS_SIEM_PROTOTYP;
using CS_DatabaseManager;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

public class ModuleStarter
{
    public static void StartApi(IDatabaseManager db)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(5000); // HTTP
            /*options.ListenAnyIP(5001, listenOptions =>
            {
                listenOptions.UseHttps(); // HTTPS
            });*/
        });
        
        builder.Services.AddEndpointsApiExplorer();
        

        var app = builder.Build();
        
        

        app.ConfigureApi(db);


        app.Run();
        
    }

    public static async void StartPrtg(IDatabaseManager db, ServiceProvider serviceProvider, string url)
    {
        var prtg = serviceProvider.GetService<PrtgReceiver>()!;
        var apiKey = "5462TDSFODTTNUP36QXMQIWIQJUED5RWNC5SSVPUZQ======";


        // creating and insert data into the database
        
        var snmpColumns = prtg.GetSensorColumnTypes();
        string primaryKey = "UUID";
        await db.CreateTable("SNMP", snmpColumns, primaryKey);
        
        // ------------------------LOOP---------------------------------
        List<Device> devices = prtg.FetchDeviceWithSensors(url, apiKey).GetAwaiter().GetResult();
        foreach (var device in devices)
        {
            await prtg.InsertSensorsAsync(device, "SNMP", snmpColumns);
        
        }
        // ------------------------LOOP---------------------------------
    }

    public static async void StartNetflow(IDatabaseManager db, ServiceProvider serviceProvider)
    {
        // nfdump muss im Hintergrund laufen (vielleicht immer den Prozess killen und neu starten)
        // StartCapturingNetFlowData
        var nf = serviceProvider.GetService<NetflowReceiver>()!;
        var nfColumns = nf.GetNetflowColumnTypes();
        string primaryKey = "UUID";
        Console.WriteLine("I AM HERE :SLLJSD");
        await db.CreateTable("Netflow", nfColumns, primaryKey);
        Console.WriteLine("I AM HERE :SLLJSD");
        string nfdump_files = "/home/mehmet/Desktop/nfdump";
        string nfdump_bin = "/bin/nfdump";
        string[] netflowPaths = NetflowReceiver.GetFilePaths(nfdump_files);
        
        
        

        foreach (string nfpath in netflowPaths)
        {
            Console.WriteLine(nfpath + " OUPUT: ");
            List<string> lines = NetflowReceiver.ProcessCapturedFile(nfpath, nfdump_bin);
//            lines.ForEach(x => Console.WriteLine(x));
            List<NetFlowData> nfDatas = NetflowReceiver.ParseNetFlowData(lines);
            Console.WriteLine("I AM HERE :SLDKFJS:DLKFJS:DLKFJSD:FKLJSD");
            foreach (var nfdata in nfDatas)
            {
                Console.WriteLine(nfdata);
            }
            await nf.InsertNfDataAsync(nfDatas, "Netflow", nfColumns);
            //MIT DATENBANK TESTEN

        }
        // move the files to a new folder (Man braucht sudo rechte also zuerste builden und dann
        // /home/sai/CS_SIEM_PROTOTYPE/CS_SIEM_PROTOTYP/bin/Debug/net8.0/CS_SIEM_PROTOTYP starten
        
        string nfDirectoryOld = nfdump_files + "/nf_files_old";
        if (!Directory.Exists(nfDirectoryOld))
        {
            Directory.CreateDirectory(nfDirectoryOld);
        }
        foreach (var netflowPath in netflowPaths)
        {
            string fileName = Path.GetFileName(netflowPath);
            string destFilePath = Path.Combine(nfDirectoryOld, fileName);
            try
            {
                
                File.Move(netflowPath, destFilePath);
                
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"I/O error occurred: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred: {ex.Message}");
            }
        }
        
        
    }
    
    public static void startSyslogReceiver(List<SyslogConfig> syslogConfigs)
    {
        foreach (var element in syslogConfigs)
        {
            
            
        }
        
    }
    
}