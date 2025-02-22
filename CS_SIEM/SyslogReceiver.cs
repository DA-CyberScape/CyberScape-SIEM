using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Cassandra;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

namespace CS_SIEM
{

    /// <summary>
    /// Receives and processes Syslog messages from network devices.
    /// </summary>
    public class SyslogReceiver
    {
        private static ConcurrentQueue<SyslogAnswer> _syslogMessagesQueue = new ConcurrentQueue<SyslogAnswer>();
        private static int _delay = 10;
        private static CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private static CancellationToken cancellationToken = _cancellationTokenSource.Token;
        private static UdpClient _udpClient;
        private IDatabaseManager _db;
        private int _port;
        private ILogger _logger;




        /// <summary>
        /// Initializes a new instance of the <see cref="SyslogReceiver"/> class.
        /// </summary>
        /// <param name="db">The database manager for inserting received Syslog messages.</param>
        /// <param name="port">The port to listen for Syslog messages.</param>
        /// <param name="logger">The logger for logging information and errors.</param>
        /// <param name="delay">The delay in seconds between inserting Syslog messages. Default is 10 seconds.</param>
        public SyslogReceiver(IDatabaseManager db, int port, ILogger logger, int delay = 10)
        {
            _db = db;
            _delay = delay;
            _port = port;
            _db.CreateTable("Syslog", GetSyslogColumnTypes(), "date, time, UUID","time DESC, UUID ASC");
            _db.CreateTable("WinEvents", GetWinEventColumnTypes(), "date, time, UUID", "time DESC, UUID ASC");
            _logger = logger;
        }


        /// <summary>
        /// Starts listening for Syslog messages on the specified port.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public async Task ReceiveSyslogData()
        {
            cancellationToken = new CancellationToken();
            _udpClient = new UdpClient(_port);
            _logger.LogInformation($"[INFO] Syslog Receiver is listening on port {_port}...");
            
            Task.Run(() => StartPeriodicDatabaseInsert(_delay, cancellationToken), cancellationToken);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Console.WriteLine($"LISTENING ON PORT {_port}");
                    // listenting part
                    IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, _port);

                    if (_udpClient.Available > 0)
                    {
                        byte[] receivedBytes = _udpClient.Receive(ref remoteEndPoint);
                        string syslogMessage = Encoding.UTF8.GetString(receivedBytes);


                        SyslogAnswer syslogAnswer =
                            ProcessSyslogMessage(syslogMessage, remoteEndPoint.Address.ToString());
                        _syslogMessagesQueue.Enqueue(syslogAnswer);
                    }
                    else
                    {
                        Thread.Sleep(500);
                    }
                    // listenting part
                }
            }
            catch (SocketException se)
            {
                _logger.LogError($"[Error] Could not bind to port {_port}: {se.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[Error] Unexpected error: {ex.Message}");
            }
            finally
            {
                _logger.LogInformation("UDP client close initiated.");
                _udpClient?.Close();
                _logger.LogInformation("UDP client closed.");
            }
        }

        /// <summary>
        /// Starts periodic insertion of Syslog messages into the database.
        /// </summary>
        /// <param name="delay">The delay in seconds between insertions.</param>
        /// <param name="token">The cancellation token to stop the task.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        private async Task StartPeriodicDatabaseInsert(int delay, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(1000 * delay, token);
                // Console.WriteLine("INSERTING EVERYTH(ING S:DLFKJSD:LFKJSD:LFKJSD:FLKJSDF");
                // Console.WriteLine(_syslogMessagesQueue.Count + " THIS WAS THE COUNT");
                await InsertMessagesIntoDatabase();
            }
        }

        /// <summary>
        /// Inserts Syslog messages from the queue into the database.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        private async Task InsertMessagesIntoDatabase()
        {
            // Console.WriteLine(" INSIDE THE INSERT METHOD IN SYSLOG");
            while (!_syslogMessagesQueue.IsEmpty)
            {
                // Console.WriteLine(" INSIDE THE INSERT METHOD IN SYSLOG AND THERE ARE THINGS IN THE QUEUE");

                if (_syslogMessagesQueue.TryDequeue(out SyslogAnswer syslogMessage))
                {
                    if (syslogMessage.Message.Length > 0)
                    {
                        _logger.LogInformation($"[INFO] Inserted message from {syslogMessage.Hostname} into database.");
                        _logger.LogInformation($"[INFO] Inserted message {syslogMessage.Message}");
                        _logger.LogInformation($"[INFO] Service: {syslogMessage.Service}");

                        // Console.WriteLine(syslogMessage.Facility + " Facility");
                        // Console.WriteLine(syslogMessage.Severity + " Severity");
                        // Console.WriteLine(syslogMessage.Hostname + " Hostname");
                        // Console.WriteLine(syslogMessage.Timestamp + " Timestamp");
                        // Console.WriteLine(syslogMessage.Message + " Message");

                        // TODO: MEHMET DB LOGIK
                        await InsertSyslogDataAsync(syslogMessage, GetSyslogColumnTypes());
                    }
                }
            }
        }

        /// <summary>
        /// Inserts Syslog data into the appropriate database table.
        /// </summary>
        /// <param name="syslogAnswer">The Syslog message data to insert.</param>
        /// <param name="columns">The column definitions for the database table.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public async Task InsertSyslogDataAsync(SyslogAnswer syslogAnswer,
            Dictionary<string, Type> columns)
        {
            var data = MapSyslogDataToData(syslogAnswer);


            try
            {
                if (data["message"].ToString().Contains("MSWinEventLog"))
                {
                    var winEventData = MapWinEventDataToData(syslogAnswer);
                    var winEventColumns = GetWinEventColumnTypes();
                    await _db.InsertData("WinEvents", winEventColumns, winEventData);
                }
                else
                {
                    await _db.InsertData("Syslog", columns, data);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to insert data {ex}");
            }
        }

        /// <summary>
        /// Gets the column types for the Syslog database table.
        /// </summary>
        /// <returns>A dictionary mapping column names to their types.</returns>
        public Dictionary<string, Type> GetSyslogColumnTypes()
        {
            return new Dictionary<string, Type>
            {
                { "srcIP", typeof(string) },
                { "time", typeof(LocalTime) },
                { "date", typeof(LocalDate) },
                { "facility", typeof(int) },
                { "severity", typeof(int) },
                { "message", typeof(string) },
                { "hostname", typeof(string) },
                { "service", typeof(string) },
                { "UUID", typeof(Guid) }
            };
        }

        /// <summary>
        /// Maps Syslog message data to a dictionary for database insertion.
        /// </summary>
        /// <param name="syslogAnswer">The Syslog message data to map.</param>
        /// <returns>A dictionary containing the mapped data.</returns>
        public Dictionary<string, object> MapSyslogDataToData(SyslogAnswer syslogAnswer)
        {
            return new Dictionary<string, object>
            {
                { "srcIP", syslogAnswer.sourceIp },
                { "time", syslogAnswer.Time },
                { "date", syslogAnswer.Date },
                { "facility", syslogAnswer.Facility },
                { "severity", syslogAnswer.Severity },
                { "message", syslogAnswer.Message },
                { "hostname", syslogAnswer.Hostname },
                { "service", syslogAnswer.Service },
                { "UUID", Guid.NewGuid() }
            };
        }

        /// <summary>
        /// Gets the column types for the Windows Event database table.
        /// </summary>
        /// <returns>A dictionary mapping column names to their types.</returns>
        public Dictionary<string, Type> GetWinEventColumnTypes()
        {
            return new Dictionary<string, Type>
            {
                { "srcIP", typeof(string) },
                { "time", typeof(LocalTime) },
                { "date", typeof(LocalDate) },
                { "facility", typeof(int) },
                { "severity", typeof(int) },
                { "message", typeof(string) },
                { "hostname", typeof(string) },
                { "eventId", typeof(string) },
                { "UUID", typeof(Guid) }
            };
        }

        /// <summary>
        /// Maps Windows Event data to a dictionary for database insertion.
        /// </summary>
        /// <param name="syslogAnswer">The Syslog message data to map.</param>
        /// <returns>A dictionary containing the mapped data.</returns>
        public Dictionary<string, object> MapWinEventDataToData(SyslogAnswer syslogAnswer)
        {
            return new Dictionary<string, object>
            {
                { "srcIP", syslogAnswer.sourceIp },
                { "time", syslogAnswer.Time },
                { "date", syslogAnswer.Date },
                { "facility", syslogAnswer.Facility },
                { "severity", syslogAnswer.Severity },
                { "message", syslogAnswer.Message },
                { "hostname", syslogAnswer.Hostname },
                { "eventId", syslogAnswer.EventId },
                { "UUID", Guid.NewGuid() }
            };
        }

        /// <summary>
        /// Stops the Syslog receiver and cancels the listening task.
        /// </summary>
        public void StopReceiver()
        {
            _logger.LogInformation(
                $"[INFO] Syslog Receiver shutdown initiated... {_cancellationTokenSource.IsCancellationRequested}");

            _cancellationTokenSource.Cancel();

            _logger.LogInformation("[INFO] Syslog Receiver shutdown initiated...");
            _udpClient?.Close();
        }

        /// <summary>
        /// Processes a received Syslog message and extracts relevant data.
        /// </summary>
        /// <param name="syslogMessage">The raw Syslog message.</param>
        /// <param name="sourceIp">The source IP address of the message.</param>
        /// <returns>A <see cref="SyslogAnswer"/> object containing the processed data.</returns
        private static SyslogAnswer ProcessSyslogMessage(string syslogMessage, string sourceIp)
        {
            SyslogAnswer syslogAnswer = new SyslogAnswer
            {
                RawMessage = syslogMessage,
                sourceIp = sourceIp,
                Service = ExtractValue("service", syslogMessage)
            };


            if (syslogMessage.Contains("MSWinEventLog"))
            {
                syslogAnswer.EventId = ExtractEventId(syslogMessage);
            }

            try
            {
                if (syslogMessage.StartsWith("<"))
                {
                    int priorityEnd = syslogMessage.IndexOf(">");
                    if (priorityEnd > 0 && int.TryParse(syslogMessage.Substring(1, priorityEnd - 1), out int priority))
                    {
                        syslogAnswer.Facility = priority / 8;
                        syslogAnswer.Severity = priority % 8;

                        string afterPriority = syslogMessage.Substring(priorityEnd + 1);
                        string[] parts = afterPriority.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 1 && int.TryParse(parts[0], out int version))
                        {
                            DateTime Timestamp = DateTime.Parse(parts[1]);
                            syslogAnswer.Date = new LocalDate(Timestamp.Year, Timestamp.Month, Timestamp.Day);
                            syslogAnswer.Time = new LocalTime(Timestamp.Hour, Timestamp.Minute, Timestamp.Second,
                                Timestamp.Millisecond * 1000000 + Timestamp.Microsecond * 1000);
                            syslogAnswer.Hostname = parts[2];
                            syslogAnswer.Message = string.Join(" ", parts.Skip(6));
                        }
                        else
                        {
                            string timestampString = afterPriority.Substring(0, 15);
                            DateTime Timestamp = DateTime.ParseExact(timestampString, "MMM dd HH:mm:ss", null);
                            // Possible Edge-Case: If a message is sent on 31st of December 2024 at 11:59:59.XX it would put it in as 31st of December 2025 
                            syslogAnswer.Date = new LocalDate(Timestamp.Year, Timestamp.Month, Timestamp.Day);
                            syslogAnswer.Time = new LocalTime(Timestamp.Hour, Timestamp.Minute, Timestamp.Second,
                                Timestamp.Millisecond * 1000000 + Timestamp.Microsecond * 1000);


                            string[] rfc3164Parts = afterPriority.Substring(16).Trim().Split(' ', 2);
                            syslogAnswer.Hostname = rfc3164Parts[0];
                            syslogAnswer.Message = rfc3164Parts.Length > 1 ? rfc3164Parts[1] : "";
                            // MEHMET WENN DU DAS JAHR BEI SO WELCHEN NACHRICHTEN AUCH HINZUFUEGEN WILLST
                            // var year = DateTime.Now.Year;
                            // DateTime timestampWithYear = new DateTime(year, parsedTimestamp.Month, parsedTimestamp.Day, parsedTimestamp.Hour, parsedTimestamp.Minute, parsedTimestamp.Second);
                            // wenn man das Jahr auch braucht
                        }
                    }
                }
                else
                {
                    // syslogAnswer.Timestamp = DateTime.UtcNow.AddHours(1);
                    DateTime Timestamp = DateTime.Now;
                    syslogAnswer.Date = new LocalDate(Timestamp.Year, Timestamp.Month, Timestamp.Day);
                    syslogAnswer.Time = new LocalTime(Timestamp.Hour, Timestamp.Minute, Timestamp.Second,
                        Timestamp.Millisecond * 1000000 + Timestamp.Microsecond * 1000);
                    Console.WriteLine(DateTime.Now.Hour + ":SLDKFJS:DLKFJS:DLKFJS:DLKFJSD:LKFJSD:LKFJSD");
                    syslogAnswer.Hostname = sourceIp;
                    syslogAnswer.Message = syslogMessage;
                }
            }
            catch
            {
                // syslogAnswer.Timestamp = DateTime.UtcNow.AddHours(1);


                DateTime Timestamp = DateTime.Now;
                syslogAnswer.Date = new LocalDate(Timestamp.Year, Timestamp.Month, Timestamp.Day);
                syslogAnswer.Time = new LocalTime(Timestamp.Hour, Timestamp.Minute, Timestamp.Second,
                    Timestamp.Millisecond * 1000000 + Timestamp.Microsecond * 1000);
                syslogAnswer.Hostname = sourceIp;
                syslogAnswer.Message = syslogMessage;
            }

            // Console.WriteLine(syslogAnswer);
            // Console.WriteLine("------------");
            // Console.WriteLine(syslogAnswer.Message);
            // Console.WriteLine(syslogAnswer.Timestamp);
            return syslogAnswer;
        }

        /// <summary>
        /// Extracts a value associated with a key from a Syslog message.
        /// </summary>
        /// <param name="key">The key to search for in the message.</param>
        /// <param name="syslogMessage">The Syslog message to search.</param>
        /// <returns>The value associated with the key, or null if not found.</returns>
        /// <exception cref="ArgumentException">Thrown if the key or message is null or empty.</exception>
        public static string? ExtractValue(string key, string syslogMessage)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(syslogMessage))
            {
                throw new ArgumentException("Key and syslog message cannot be null or empty.");
            }


            string pattern = $@"{key}=(?<value>\S+)";
            Match match = Regex.Match(syslogMessage, pattern);

            if (match.Success)
            {
                return match.Groups["value"].Value;
            }

            return null;
        }

        /// <summary>
        /// Extracts the event ID from a Windows Event Log message.
        /// </summary>
        /// <param name="message">The message to search.</param>
        /// <returns>The event ID, or null if not found.</returns>
        public static string? ExtractEventId(string message)
        {
            string pattern = @"(?<eventid>\d+)\s[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}";


            Match match = Regex.Match(message, pattern);

            if (match.Success)
            {
                return match.Groups["eventid"].Value;
            }

            return null;
        }

        /// <summary>
        /// Tests the <see cref="ProcessSyslogMessage"/> method with sample data.
        /// </summary>
        public static void TestProcessSyslogMessage()
        {
            List<(string Message, string sourceIp)> testData = new List<(string, string)>
            {
                ("<34>Oct 18 14:32:16 myhost su: 'su root' failed for user on /dev/pts/2", "192.168.1.50"),
                ("<165>1 2024-10-18T14:33:44.003Z myapp.example.com MyApp 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] User login attempt failed",
                    "10.0.0.25"),
                ("<13>Oct 18 14:35:02 firewall.local kernel: IPTables packet dropped: SRC=192.168.2.10 DST=192.168.1.100 PROTO=TCP SPT=445 DPT=80",
                    "172.16.10.100"),
                ("<14>Oct 18 14:36:50 app-server.local myapp: [WARNING] Memory usage exceeded threshold: current usage at 85%",
                    "203.0.113.45"),
                ("This is a raw syslog message without any standard format.", "192.168.0.10")
            };

            foreach (var (message, sourceIp) in testData)
            {
                Console.WriteLine("[TEST] Processing Syslog Message:");
                SyslogAnswer result = ProcessSyslogMessage(message, sourceIp);
                Console.WriteLine(result);
                Console.WriteLine(new string('-', 50));
            }
        }
    }

    /// <summary>
    /// Represents the configuration for a Syslog receiver.
    /// </summary>
    public class SyslogConfig
    {
        /// <summary>
        /// Gets or sets the port to listen for Syslog messages.
        /// </summary>
        public int Port { get; set; }
        /// <summary>
        /// Gets or sets the name of the Syslog receiver.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// Gets or sets the ID of the Syslog receiver.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Returns a string representation of the Syslog configuration.
        /// </summary>
        /// <returns>A string containing the port, ID, and name of the configuration.</returns>
        public override string ToString()
        {
            return $"Port: {Port}, Id: {Id}, Name: {Name}";
        }
    }

    /// <summary>
    /// Represents the processed data of a Syslog message.
    /// </summary>
    public class SyslogAnswer
    {
        /// <summary>
        /// Gets or sets the date of the Syslog message.
        /// </summary>
        public LocalDate? Date { get; set; }
        /// <summary>
        /// Gets or sets the time of the Syslog message.
        /// </summary>
        public LocalTime? Time { get; set; }
        /// <summary>
        /// Gets or sets the hostname of the Syslog message.
        /// </summary>
        public string? Hostname { get; set; }
        /// <summary>
        /// Gets or sets the message content of the Syslog message.
        /// </summary>
        public string? Message { get; set; }
        /// <summary>
        /// Gets or sets the facility code of the Syslog message.
        /// </summary>
        public int Facility { get; set; }
        /// <summary>
        /// Gets or sets the severity level of the Syslog message.
        /// </summary>
        public int Severity { get; set; }
        /// <summary>
        /// Gets or sets the source IP address of the Syslog message.
        /// </summary>
        public string? sourceIp { get; set; }
        /// <summary>
        /// Gets or sets the raw Syslog message.
        /// </summary>
        public string? RawMessage { get; set; }
        /// <summary>
        /// Gets or sets the service associated with the Syslog message.
        /// </summary>

        public string? Service { get; set; }
        /// <summary>
        /// Gets or sets the event ID for Windows Event Log messages.
        /// </summary>
        public string? EventId { get; set; }

        /// <summary>
        /// Returns a string representation of the Syslog message data.
        /// </summary>
        /// <returns>A string containing the date, time, hostname, facility, severity, source IP, and message.</returns>
        public override string ToString()
        {
            return
                $"[{Date} {Time}] {Hostname} (Facility: {Facility}, Severity: {Severity}, Source: {sourceIp}): {Message} ";
        }
    }
}