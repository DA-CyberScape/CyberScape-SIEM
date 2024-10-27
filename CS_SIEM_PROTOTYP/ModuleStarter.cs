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

    
    
}