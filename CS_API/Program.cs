using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateSlimBuilder(args);

// Configure JSON options with custom serializer context (DEFINITIV OHNE CHATGPT)
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolver = AppJsonSerializerContext.Default;
});

var app = builder.Build();

// Directory where JSON files will be stored
var configDirectory = Path.Combine(Directory.GetCurrentDirectory(), "configurations_example");

// Ensure the directory exists
if (!Directory.Exists(configDirectory))
{
    Directory.CreateDirectory(configDirectory);
}


app.MapGet("/configurations", () =>
{
    var files = Directory.GetFiles(configDirectory, "*.json");

    // Check if there are any files in the directory
    if (files.Length == 0)
    {
        return Results.NotFound("No configuration files found.");
    }

    // Get the first JSON file
    var firstFile = files[0];
    var jsonContent = File.ReadAllText(firstFile);

    // Return the contents of the first file
    return Results.Content(jsonContent, "application/json");
});


// POST request to add a new JSON file with the content of the body
app.MapPost("/configurations", async (HttpRequest request) =>
{
    // Read the raw JSON content from the request body
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();

    // Specify a filename, e.g., using "example_API.json"
    var newFileName = Path.Combine(configDirectory, "example_API.json");

    // Write the JSON content to a file, replacing the old file
    await File.WriteAllTextAsync(newFileName, jsonContent);

    // Return a response indicating success
    return Results.Ok(new { Message = "Configuration saved successfully.", FileName = "example_API.json" });
});

app.Run();

public record Configuration(string Name, string Version, bool Enabled, Dictionary<string, string> Settings);

// JSON serialization context for custom types
[JsonSerializable(typeof(Configuration))]
[JsonSerializable(typeof(List<Configuration>))] // Add this for List<Configuration>
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}