using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using CS_API;
using CS_SIEM_PROTOTYP;
using CS_DatabaseManager;

//----------------------------------------------------------------------
string apiConfigurationFile = "apiConfiguration.json";
string hostAssignmentFile = "hostAssignment.json";
var configDirectory = Path.Combine(Directory.GetCurrentDirectory(), "/home/cyberscape_admin/CyberScape-SIEM/CS_API/Configurations_Example");
var defaultConfigurationPath = Path.Combine(configDirectory, apiConfigurationFile);

var assignmentDirectory = Path.Combine(Directory.GetCurrentDirectory(), "/home/cyberscape_admin/CyberScape-SIEM/CS_API/HostAssignment");
var defaultAssignmentPath = Path.Combine(assignmentDirectory, hostAssignmentFile);

if (!Directory.Exists(configDirectory))
{
    Directory.CreateDirectory(configDirectory);
    Console.WriteLine("Please create the File: " + apiConfigurationFile + " in the Folder: "+configDirectory);
    return;
}

if (!File.Exists(defaultConfigurationPath))
{
    Console.WriteLine("Please create the File: " + apiConfigurationFile + " in the Folder: "+configDirectory);
    return;
}

if (!Directory.Exists(assignmentDirectory))
{
    Directory.CreateDirectory(assignmentDirectory);
    Console.WriteLine("Please create the File: " + hostAssignmentFile + " in the Folder: "+assignmentDirectory);
    return;
}

if (!File.Exists(defaultAssignmentPath))
{
    Console.WriteLine("Please create the File: " + hostAssignmentFile + " in the Folder: "+assignmentDirectory);
    return;
}

//----------------------------------------------------------------------

var builder = WebApplication.CreateSlimBuilder(args);

// sagt dem Programm dass ein custom serialization context genutzt wird
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolver = AppJsonSerializerContext.Default;
});

var app = builder.Build();
var ps = new ProcessStarter();

// Diese Variable hat den CancellationTokenSource damit das Program gescheiht gestoppt werden kann
CancellationTokenSource cts = new CancellationTokenSource();
// SIEM wird zum ersten Mal ausgefuehrt (startup)
await Task.Run(() => ps.StartProcessAsync(defaultConfigurationPath, cts.Token));




app.MapGet("/configurations", () =>
{
    var apiConfigurationPath = Path.Combine(configDirectory, apiConfigurationFile);
    if (!File.Exists(apiConfigurationPath))
    {
        return Results.NotFound("Host assignment file not found.");
    }
    var jsonContent = File.ReadAllText(apiConfigurationPath);
    return Results.Content(jsonContent, "application/json");
});

// POST request to add a new configuration
app.MapPost("/configurations", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    var newApiConfigurationFile = Path.Combine(configDirectory, apiConfigurationFile);
    
    Console.WriteLine(newApiConfigurationFile);
    Console.WriteLine(jsonContent);
    
    await File.WriteAllTextAsync(newApiConfigurationFile, jsonContent);
    ps.StopProcess();
    
    cts = new CancellationTokenSource();
    await Task.Run(() => ps.StartProcessAsync(newApiConfigurationFile, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarted SIEM with new Configuration",
        "apiConfiguration.json");
    return Results.Ok(response);
});

app.MapGet("/host_assignment", () =>
{
    var hostAssignmentPath = Path.Combine(assignmentDirectory, hostAssignmentFile);
    if (!File.Exists(hostAssignmentPath))
    {
        return Results.NotFound("Host assignment file not found.");
    }
    var jsonContent = File.ReadAllText(hostAssignmentPath);
    return Results.Content(jsonContent, "application/json");
});

app.MapPost("/host_assignment", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    var newHostAssignmentFile = Path.Combine(assignmentDirectory, hostAssignmentFile);

    Console.WriteLine("Updating host assignment:");
    Console.WriteLine(jsonContent);
    
    /*
    ps.StopProcess();
    await File.WriteAllTextAsync(newHostAssignmentFile, jsonContent);
    
    cts = new CancellationTokenSource();
    await Task.Run(() => ps.StartProcessAsync(newHostAssignmentFile, cts.Token));*/

    var response = new SaveResponse("Host assignment updated successfully. Restarting SIEM with new host assignment.",
        "hostAssignmentDirectory.json");
    return Results.Ok(response);
});































//TODO Scylla Configuration hinzufügen
app.MapGet("/configurations/Database", () =>
{
    var lFiles = Directory.GetFiles("../App_Configurations", "Database_IPs.yaml");
    
    if (lFiles.Length == 0)
    {
        return Results.NotFound("No configuration files found.");
    }

    var firstFile = lFiles[0];
    var yamlContent = File.ReadAllText(firstFile);
    var xyz = yamlContent.Split("\n");
    var returnContent = "";
    foreach (String s in xyz)
    {
        if (!s.StartsWith('#') || s.Equals(""))
        {
            returnContent += s + "\n";
        }
    }
    
    return Results.Content(returnContent, "application/json");
});


app.MapPost("/configurations/Database", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    var newFileName = Path.Combine("App_Configurations", "Database_IPs.yaml");
    Console.WriteLine(newFileName);

    await File.WriteAllTextAsync(newFileName, jsonContent);
    ps.StopProcess();
    await Task.Delay(10_000);

    cts = new CancellationTokenSource();
    await Task.Run(() => ps.StartProcessAsync(newFileName, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarting SIEM with new Configuration",
        "apiConfiguration.json");
    return Results.Ok(response);
});

app.Run();


public record Configuration(string Name, string Version, bool Enabled, Dictionary<string, string> Settings);

public record SaveResponse(string Message, string FileName);


[JsonSerializable(typeof(Configuration))]
[JsonSerializable(typeof(SaveResponse))]
[JsonSerializable(typeof(List<Configuration>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}