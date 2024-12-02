using System.Text.Json;
using System.Text.Json.Serialization;
using CS_SIEM_PROTOTYP;

namespace CS_SIEM_PROTOTYP
{
    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Default)]
    [JsonSerializable(typeof(QueryResponse))]
    public partial class MyJsonContext : JsonSerializerContext
    {
    }
    public class QueryResponse
    {
        public List<Dictionary<string, string>> Rows { get; set; } // Change object to string
    }
}
