namespace CS_API;
using System.Text.Json;
using System.Text.Json.Serialization;
using CS_DatabaseManager;

public class AlertUpdater
{
    private readonly string _json;
    
    public AlertUpdater(string json)
    {
        _json = json;
    }

    public void AddAlert()
    {
    }

}