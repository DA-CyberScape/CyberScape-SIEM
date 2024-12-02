using System.Text.Json;
using System.Text.Json.Serialization;
using CS_API;
using System.IdentityModel.Tokens.Jwt;


var builder = WebApplication.CreateSlimBuilder(args);

// Configure JSON options with custom serializer context
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolver = AppJsonSerializerContext.Default;
});

// builder.Services.AddAuthentication(options => { options.DefaultAuthenticateScheme = JwtB})

var app = builder.Build();

// Directory setup
var configDirectory = Path.Combine(Directory.GetCurrentDirectory(),
    "/home/cyberscape_admin/CyberScape-SIEM/CS_API/Configurations_Example");

if (!Directory.Exists(configDirectory))
{
    Directory.CreateDirectory(configDirectory);
}

// This variable will hold the cancellation token for stopping the process
CancellationTokenSource cts = new CancellationTokenSource();

// SIEM wird zum ersten Mal ausgefuehrt (startup)
var files = Directory.GetFiles(configDirectory, "*.json");
if (files.Length > 0)
{
    var firstFile = files[0];
    Task.Run(() => ProcessStarter.StartProcessAsync(firstFile, cts.Token));
}


app.MapGet("/configurations", () =>
{
    var files = Directory.GetFiles(configDirectory, "*.json");

    if (files.Length == 0)
    {
        return Results.NotFound("No configuration files found.");
    }

    var firstFile = files[0];
    var jsonContent = File.ReadAllText(firstFile);

    return Results.Content(jsonContent, "application/json");
});

// POST request to add a new configuration
app.MapPost("/configurations", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    var newFileName = Path.Combine(configDirectory, "example_API.json");
    Console.WriteLine(newFileName);

    await File.WriteAllTextAsync(newFileName, jsonContent);
    ProcessStarter.StopProcess();
    await Task.Delay(10_000);

    cts = new CancellationTokenSource();
    Task.Run(() => ProcessStarter.StartProcessAsync(newFileName, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarting SIEM with new Configuration",
        "example_API.json");
    return Results.Ok(response);
});

//TODO Scylla Configuration hinzufügen
app.MapPost("/configurations/Scylla", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    var newFileName = Path.Combine("App_Configurations", "Database_IPs.yaml");
    Console.WriteLine(newFileName);

    await File.WriteAllTextAsync(newFileName, jsonContent);
    ProcessStarter.StopProcess();
    await Task.Delay(10_000);

    cts = new CancellationTokenSource();
    Task.Run(() => ProcessStarter.StartProcessAsync(newFileName, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarting SIEM with new Configuration",
        "example_API.json");
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