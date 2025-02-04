using Cassandra;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;
namespace CS_SIEM_PROTOTYP;

public class CustomApiFetcher(List<CustomApiElement> customApiElements, IDatabaseManager databaseManager, ILogger logger)
{
    private readonly List<CustomApiElement> _customApiElements = customApiElements;
    private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
    private readonly int _delay = 10;
    private readonly IDatabaseManager _databaseManager = databaseManager;
    private readonly ILogger _logger = logger;

    

    public async void StartCustomApiFetcher()
    {
        try
        {
            await _databaseManager.CreateTable("CustomApi", GetApiAnswerColumnTypes(), "date, time, UUID", "time DESC, UUID ASC");
            _logger.LogInformation("STARTED CUSTOMAPIFETCHER");
            var cancellationToken = _cancellationTokenSource.Token;

            while (!cancellationToken.IsCancellationRequested)
            {
                foreach (var apiElement in _customApiElements)
                {
          


                    string answer = "";
                    string apiEndpoint = apiElement.Url;
                    using (HttpClientHandler handler = new HttpClientHandler())
                    {
                        handler.ServerCertificateCustomValidationCallback =
                            (message, cert, chain, sslPolicyErrors) => true;
                        using (HttpClient client = new HttpClient(handler))
                        {
                            try
                            {
                                if (!string.IsNullOrEmpty(apiElement.Token))
                                {
                                    _logger.LogInformation($"USING TOKEN");
                                    client.DefaultRequestHeaders.Authorization =
                                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer",
                                            apiElement.Token);
                                }

                                _logger.LogInformation($"Fetching data from {apiEndpoint}");
                                HttpResponseMessage response = await client.GetAsync(apiEndpoint, cancellationToken);
                                response.EnsureSuccessStatusCode();

                                answer = await response.Content.ReadAsStringAsync(cancellationToken);
                                _logger.LogInformation($"Received response: {answer}");
                            }
                            catch (HttpRequestException e)
                            {
                                _logger.LogError($"Request error: {e.Message}");
                            }
                        }
                    }

                    if (answer != "[]" && answer != "")
                    {
                   
                        var timestamp = DateTime.Now;
                        var ltime = new LocalTime(timestamp.Hour, timestamp.Minute, timestamp.Second, timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000);
                        var ldate = new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day);
                  
                        ApiAnswer apiAnswer = new ApiAnswer(answer, apiElement.Url, ltime, ldate);
        
                        _logger.LogInformation($"{apiAnswer}");
                        await InsertApiAnswerAsync(apiAnswer, "CustomApi", GetApiAnswerColumnTypes());
                    }
                }
            
                try
                {
                    _logger.LogInformation($"WAITING FOR {_delay} seconds");
                    await Task.Delay(_delay * 1000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    _logger.LogInformation("CUSTOMAPIFETCHER STOPPED GRACEFULLY");
                    return;
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            _logger.LogError($"Request error: {e.Message}");
        }
    }

    private async Task InsertApiAnswerAsync(ApiAnswer apiAnswer, string table, Dictionary<string, Type> columns)
    {
        var data = MapApiAnswerToDictionary(apiAnswer);
        
        try
        {
            await _databaseManager.InsertData(table, columns, data);
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to insert data in CUSTOM API FETCHER: {ex.Message}");
        }
    }
    
    public void StopCustomApiFetcher()
    {
        _logger.LogInformation("STOPPING CUSTOMAPIFETCHER");
        if (!_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            _logger.LogInformation("CUSTOMAPIFETCHER is stopping");
        }
        _logger.LogInformation("STOPPED CUSTOMAPIFETCHER");
    }

    private static Dictionary<string, Type> GetApiAnswerColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "content", typeof(string) },
            { "url", typeof(string) },
            { "time", typeof(LocalTime) },
            { "date", typeof(LocalDate) },
            { "UUID", typeof(Guid) }
        };
    }

    private Dictionary<string, object> MapApiAnswerToDictionary(ApiAnswer apiAnswer)
    {
        return new Dictionary<string, object>
        {
            { "content", apiAnswer.Content },
            { "url", apiAnswer.Url },
            { "time", apiAnswer.Time! },
            { "date", apiAnswer.Date! },
            { "UUID", Guid.NewGuid() }
        };
    }
}

public class CustomApiElement(string url, string token = "")
{
    public string Url { get; set; } = url;
    public string Token { get; set; } = token;

    public override string ToString()
    {
        return $"Request URL: {Url} with the Token {Token}";
    }
}

public class ApiAnswer(string content, string url, LocalTime time, LocalDate date)
{
    public string Content { get; set; } = content;
    public string Url { get; set; } = url;
    public LocalDate? Date { get; set; } = date;
    public LocalTime? Time { get; set; } = time;
    
    public override string ToString()
    {
        return $"Request URL: {Url} with the Content {Content}";
    }
}