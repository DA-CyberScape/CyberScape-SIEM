using CS_DatabaseManager;
using Microsoft.Extensions.Logging;
using Cassandra;

namespace CS_SIEM;

/// <summary>
/// Class responsible for fetching data from APIs and storing the responses in a database.
/// Mainly used to request Data from the Access Point
/// </summary>
/// <param name="customApiElements">List of API elements containing URL and Token information.</param>
/// <param name="databaseManager">Database manager instance to handle database operations.</param>
/// <param name="logger">Logger instance for logging operations.</param>
public class CustomApiFetcher(List<CustomApiElement> customApiElements, IDatabaseManager databaseManager, ILogger logger)
{
    private readonly List<CustomApiElement> _customApiElements = customApiElements;
    private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
    private readonly int _delay = 10;
    private readonly IDatabaseManager _databaseManager = databaseManager;
    private readonly ILogger _logger = logger;



    /// <summary>
    /// Starts the API fetcher asynchronously, fetching data at a set interval and storing it in the database.
    /// Starts with checking if the Table exists in Database exists creates the Table if necessary.
    /// Iterates through the list of API Endpoints to fetch and fetches their information.
    /// Saves all the received Data in the database table created at the start.
    /// Calls <see cref="InsertApiAnswerAsync(ApiAnswer, string, Dictionary{string, Type})"/> to insert the data
    /// </summary>
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

    /// <summary>
    /// Inserts API response data into the database.
    /// </summary>
    /// <param name="apiAnswer">API response data.</param>
    /// <param name="table">Database table name.</param>
    /// <param name="columns">Column definitions.</param>
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
    /// <summary>
    /// Stops the API fetcher.
    /// </summary>
    
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
    /// <summary>
    /// Defines the database column types for API responses.
    /// </summary>
    /// <returns>A dictionary mapping column names to data types.</returns>
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

    /// <summary>
    /// Maps an API response to a dictionary for database insertion.
    /// </summary>
    /// <param name="apiAnswer">API response object.</param>
    /// <returns>A dictionary representation of the API response.</returns>
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

/// <summary>
/// Represents a custom API element with a URL and optional token.
/// </summary>
public class CustomApiElement(string url, string token = "")
{
    /// <summary>
    /// Gets or sets the URL.
    /// </summary>
    public string Url { get; set; } = url;

    /// <summary>
    /// Gets or sets the Token.
    /// </summary>
    public string Token { get; set; } = token;

    /// <summary>
    /// Overrides the toString method
    /// </summary>
    /// <returns>a string with the url and the token</returns>
    public override string ToString()
    {
        return $"Request URL: {Url} with the Token {Token}";
    }
}

/// <summary>
/// Represents an API response.
/// </summary>
public class ApiAnswer(string content, string url, LocalTime time, LocalDate date)
{
    /// <summary>
    /// Gets or sets the content.
    /// </summary>
    public string Content { get; set; } = content;

    /// <summary>
    /// Gets or sets the URL.
    /// </summary>
    public string Url { get; set; } = url;

    /// <summary>
    /// Gets or sets the Date.
    /// </summary>
    public LocalDate? Date { get; set; } = date;

    /// <summary>
    /// Gets or sets the Time.
    /// </summary>
    public LocalTime? Time { get; set; } = time;

    /// <summary>
    /// Overrides the toString method
    /// </summary>
    /// <returns>a string with the url and the content</returns>
    public override string ToString()
    {
        return $"Request URL: {Url} with the Content {Content}";
    }
}