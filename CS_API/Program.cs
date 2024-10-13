using System.Text.Json;
using System.Text.Json.Serialization;
using CS_API;

var builder = WebApplication.CreateSlimBuilder(args);

// Configure JSON options with custom serializer context
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolver = AppJsonSerializerContext.Default;
});

var app = builder.Build();

// Directory setup
var configDirectory = Path.Combine(Directory.GetCurrentDirectory(), "configurations_example");

if (!Directory.Exists(configDirectory))
{
    Directory.CreateDirectory(configDirectory);
}

// This variable will hold the cancellation token for stopping the process
CancellationTokenSource cts = new CancellationTokenSource();

// On startup, start the process with the first configuration asynchronously
var files = Directory.GetFiles(configDirectory, "*.json");
if (files.Length > 0)
{
    var firstFile = files[0];
    Task.Run(() => ProcessStarter.StartProcessAsync(firstFile, cts.Token));
}

// GET request to retrieve configurations
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
    // Console.WriteLine(1);
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    // Console.WriteLine(2);

    var newFileName = Path.Combine(configDirectory, "example_API.json");
    // Console.WriteLine(3);

    await File.WriteAllTextAsync(newFileName, jsonContent);
    // Console.WriteLine(4);
    
    ProcessStarter.StopProcess();

    // Start the new process asynchronously
    cts = new CancellationTokenSource(); // Create a new CancellationTokenSource for the new task
    Task.Run(() => ProcessStarter.StartProcessAsync(newFileName, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarting SIEM with new Configuration", "example_API.json");
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