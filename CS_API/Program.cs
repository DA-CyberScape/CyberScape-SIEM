using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using CS_API;
using CS_SIEM;
using CS_DatabaseManager;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using Microsoft.Extensions.Logging;



string apiConfigurationFile = "apiConfiguration.json";
string apiConfigurationSchemaFile = "apiConfigurationSchema.json";
string hostAssignmentFile = "hostAssignment.json";
string hostAssignmentSchemaFile = "hostAssignmentSchema.json";
string vlanAssignmentFile = "vlanAssignment.json";
string vlanAssignmentSchemaFile = "vlanAssignmentSchema.json";
string alertsFile = "alerts.json";
string alertsPostSchemaFile = "alertsPostSchema.json";


string baseDirectory = Directory.GetCurrentDirectory();
string configDirectory = Path.Combine(baseDirectory, "Configuration");
string assignmentDirectory = Path.Combine(baseDirectory, "HostAssignment");
string alertsDirectory = Path.Combine(baseDirectory, "Alerts");
string vlanAssignmentDirectory = Path.Combine(baseDirectory, "VlanAssignment");

string defaultConfigurationPath = Path.Combine(configDirectory, apiConfigurationFile);
string apiConfigurationSchemaPath = Path.Combine(configDirectory, apiConfigurationSchemaFile);
string defaultAssignmentPath = Path.Combine(assignmentDirectory, hostAssignmentFile);
string defaultAssignmentSchemaPath = Path.Combine(assignmentDirectory, hostAssignmentSchemaFile);
string defaultAlertsPath = Path.Combine(alertsDirectory, alertsFile);
string alertsPostSchemaPath = Path.Combine(alertsDirectory, alertsPostSchemaFile);
string defaultVlanAssignmentPath = Path.Combine(vlanAssignmentDirectory, vlanAssignmentFile);
string defaultVlanAssignmentSchemaPath = Path.Combine(vlanAssignmentDirectory, vlanAssignmentSchemaFile);



HostTableUpdater.CreateTable();
VlanTableUpdater.CreateTable();

if (!CheckFile(defaultConfigurationPath, apiConfigurationFile))
    return;
if (!CheckFile(defaultConfigurationPath, apiConfigurationSchemaFile))
    return;

if (!CheckFile(defaultAssignmentPath, hostAssignmentFile))
    return;

if (!CheckFile(defaultAssignmentSchemaPath, hostAssignmentSchemaFile))
    return;

if (!CheckFile(defaultAlertsPath, alertsFile))
    return;

if (!CheckFile(alertsPostSchemaPath, alertsPostSchemaFile))
    return;

if (!CheckFile(defaultVlanAssignmentPath, vlanAssignmentFile))
    return;
if (!CheckFile(defaultVlanAssignmentSchemaPath, vlanAssignmentSchemaFile))
    return;

bool CheckFile(string filePath, string fileName)
{
    if (!File.Exists(filePath))
    {
        Console.WriteLine($"Please create the file: {fileName} in the folder: {Path.GetDirectoryName(filePath)}");
        return false;
    }

    return true;
}



string currentAlertsJson = File.ReadAllText(defaultAlertsPath);
// alertsDictionary
List<Dictionary<string, object>> alertsListDictionary = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(currentAlertsJson);
AlertChecker alertChecker = new AlertChecker(alertsListDictionary);
alertChecker.AlertsPath = defaultAlertsPath;
alertChecker.StartAlertChecker();
//----------------------------------------------------------------------

var builder = WebApplication.CreateSlimBuilder(args);

var certificateFile = Path.Combine(Directory.GetCurrentDirectory(), "Certificates/certificate_self_signed.pfx");

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5073);

    
    if (File.Exists(certificateFile))
    {
        options.ListenAnyIP(5072, listenOptions =>
        {
            listenOptions.UseHttps(certificateFile, "junioradmin");
        });
        Console.WriteLine("Certificate file FOUND. HTTPS endpoint will be enabled.");
    }
    else
    {
        Console.WriteLine("Certificate file not found. HTTPS endpoint will not be enabled.");
    }
});


builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolver = AppJsonSerializerContext.Default;
});
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", b =>
    {
        b.AllowAnyOrigin()
            .AllowAnyMethod() 
            .AllowAnyHeader(); 
    });
});
builder.Services.AddControllers();

var app = builder.Build();
app.UseCors("AllowAll"); 
app.MapControllers();

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
    
    string schemaJson = File.ReadAllText(apiConfigurationSchemaPath);
    JSchema schema = JSchema.Parse(schemaJson);
    if (!IsJsonArrayValid(jsonContent, schema, out string validationErrors))
    {
        return Results.BadRequest($"Invalid JSON: {validationErrors}");
    }
    
    
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
// ---------------------------------HOST---------------------------------
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
    string schemaJson = File.ReadAllText(defaultAssignmentSchemaPath);
    var schema = JSchema.Parse(schemaJson);
    
    if (!IsJsonValid(jsonContent, schema, out string validationErrors))
    {
        return Results.BadRequest($"Invalid JSON: {validationErrors}");
    }
    var newHostAssignmentFile = Path.Combine(assignmentDirectory, hostAssignmentFile);
    await File.WriteAllTextAsync(newHostAssignmentFile, jsonContent);

    HostTableUpdater htu = new HostTableUpdater(jsonContent);
    htu.UpdateHostTable();
    
    
    Console.WriteLine("Updating host assignment:");
    Console.WriteLine(jsonContent);
    var response = new SaveResponse("Host assignment updated successfully.",
        newHostAssignmentFile);
    return Results.Ok(response);
});
// ---------------------------------HOST---------------------------------

app.MapGet("/vlan_assignment", () =>
{
    var vlanAssignmentPath = defaultVlanAssignmentPath;
    if (!File.Exists(vlanAssignmentPath))
    {
        return Results.NotFound("VLAN assignment file not found.");
    }
    var jsonContent = File.ReadAllText(vlanAssignmentPath);
    return Results.Content(jsonContent, "application/json");
});

// POST endpoint to update VLAN assignments
app.MapPost("/vlan_assignment", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();

    string schemaJson = File.ReadAllText(defaultVlanAssignmentSchemaPath);
    var schema = JSchema.Parse(schemaJson);

    // Validate the JSON content against the schema
    if (!IsJsonValid(jsonContent, schema, out string validationErrors))
    {
        return Results.BadRequest($"Invalid JSON: {validationErrors}");
    }

    // Save the updated VLAN assignments to the file
    var newVlanAssignmentFile = Path.Combine(vlanAssignmentDirectory, vlanAssignmentFile);
    await File.WriteAllTextAsync(newVlanAssignmentFile, jsonContent);

    // Update the "Vlans" table in the database
    VlanTableUpdater vtu = new VlanTableUpdater(jsonContent);
    vtu.UpdateVlanTable();

    Console.WriteLine("Updating VLAN assignment:");
    Console.WriteLine(jsonContent);

    var response = new SaveResponse("VLAN assignment updated successfully.",
        newVlanAssignmentFile);
    return Results.Ok(response);
});











app.MapGet("/alerts", () =>
{
    var alertsPath = Path.Combine(alertsDirectory, alertsFile);
    if (!File.Exists(alertsPath))
    {
        return Results.NotFound("Alerts file not found.");
    }
    var jsonContent = File.ReadAllText(alertsPath);
    return Results.Content(jsonContent, "application/json");
});

app.MapPost("/alerts", async (HttpRequest request) =>
{


    //json vom body bekommen
    using var reader = new StreamReader(request.Body);
    var jsonContent = await reader.ReadToEndAsync();
    Console.WriteLine("-------------------------------------------");
    Console.WriteLine(jsonContent);
    Console.WriteLine("-------------------------------------------");
    // schema vom file bekommen
    string schemaJson = File.ReadAllText(alertsPostSchemaPath);
    JSchema schema = JSchema.Parse(schemaJson);
    if (!IsJsonValid(jsonContent, schema, out string validationErrors))
    {
        return Results.BadRequest($"Invalid JSON: {validationErrors}");
    }
    var newAlertsFilePath = Path.Combine(alertsDirectory, alertsFile);
    // neues alert wird in das dictionary hinzugefuegt
    Dictionary<string, object> newAlertsElement = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonContent);
    alertChecker.ListOfAlerts.Add(newAlertsElement);
    
    alertChecker.RestartAlertChecker();

    

    // die ganze liste an alerts wird in ein JSON umgewandelt und in das Alert File reingeschrieben
    string newAlertsJson = JsonConvert.SerializeObject(alertChecker.ListOfAlerts, Formatting.Indented);
    await File.WriteAllTextAsync(newAlertsFilePath, newAlertsJson);
    Console.WriteLine("WORKIGN 5");

    
    
    // -------------DEBUGGING ZEUG------------- 
    Console.WriteLine("Updating Alerts Table");
    Console.WriteLine(jsonContent);
    Console.WriteLine("All Alerts: ");
    
    foreach (var item in alertChecker.ListOfAlerts)
    {
        Console.WriteLine("---- New Entry ----");
        foreach (var keyValue in item)
        {
            Console.WriteLine($"{keyValue.Key}: {keyValue.Value}");
        }
    }
    // -------------DEBUGGING ZEUG------------- 
    var response = new SaveResponse("Alerts Table updated successfully.",
        "alerts.json");
    return Results.Ok(response);
});

app.MapDelete("/alerts/{id:long}", async (long id) =>
{
    Console.WriteLine("-----------------DELETING-EVERYTHING-----------------");
    if (id <= 0)
    {
        return Results.BadRequest("ID must be a positive integer.");
    }
  
    // Alle Elemente mit der ID id werden geloescht
    List<Dictionary<string, object>> listToRemove = new List<Dictionary<string, object>>();
    foreach (var element in alertChecker.ListOfAlerts)
    {
        if (element["id"].ToString() == id.ToString())
        {
            listToRemove.Add(element);
        }
    }
    alertChecker.ListOfAlerts.RemoveAll(item => listToRemove.Contains(item));
    
    string newAlertsJson = JsonConvert.SerializeObject(alertChecker.ListOfAlerts, Formatting.Indented);
    var newAlertsFilePath = Path.Combine(alertsDirectory, alertsFile);
    await File.WriteAllTextAsync(newAlertsFilePath, newAlertsJson);
    
    
    alertChecker.RestartAlertChecker();
   
    // -------------DEBUGGING ZEUG------------- 
    Console.WriteLine("Updating Alerts Table:");
    foreach (var item in alertChecker.ListOfAlerts)
    {
        Console.WriteLine("---- New Entry ----");
        foreach (var keyValue in item)
        {
            Console.WriteLine($"{keyValue.Key}: {keyValue.Value}");
        }
    }
    // -------------DEBUGGING ZEUG------------- 
    var response = new SaveResponse($"Deleted all Alerts with the ID {id}.",
            "alerts.json");
    return Results.Ok(response);
});

bool IsJsonValid(string jsonContent, JSchema schema, out string validationErrors)
{
    try
    {
        var jsonObject = JObject.Parse(jsonContent);

        // Validate JSON against the schema
        var isValid = jsonObject.IsValid(schema, out IList<string> errors);
        validationErrors = string.Join("; ", errors);
        return isValid;
    }
    catch (JsonReaderException)
    {
        validationErrors = "Invalid JSON structure.";
        return false;
    }
}

bool IsJsonArrayValid(string jsonContent, JSchema schema, out string validationErrors)
{
    try
    {
        var jsonArray = JArray.Parse(jsonContent);

        // Validate JSON against the schema
        var isValid = jsonArray.IsValid(schema, out IList<string> errors);
        validationErrors = string.Join("; ", errors);
        return isValid;
    }
    catch (JsonReaderException)
    {
        validationErrors = "Invalid JSON ARRAY structure.";
        return false;
    }
}































//TODO Scylla Configuration hinzufügen
app.MapGet("/configurations/Database", () =>
{
    var lFiles = Directory.GetFiles("../App_Configurations", "Database_IPs.test.yaml");
    
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
    var newFileName = Path.Combine("../App_Configurations", "Database_IPs.test.yaml");
    Console.WriteLine(newFileName);
    Console.WriteLine(jsonContent);
    await File.WriteAllTextAsync(newFileName, jsonContent);
    ps.StopProcess();
    await Task.Delay(10_000);

    cts = new CancellationTokenSource();
    await Task.Run(() => ps.StartProcessAsync(newFileName, cts.Token));

    var response = new SaveResponse("Configuration saved successfully. Restarting SIEM with new Configuration",
        "apiConfiguration.json");
    return Results.Ok(response);
});

app.MapGet("/configurations/Database/schema", async () =>
{
    DbHostProvider dbHost = new DbHostProvider();
    ScyllaDatabaseManager db = new ScyllaDatabaseManager(dbHost);

    var schema = await db.GetSchema();
    string json = JsonConvert.SerializeObject(schema, Formatting.Indented);
    
    return Results.Content(json, "application/json");
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