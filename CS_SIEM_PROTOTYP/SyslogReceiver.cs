using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Timers;
using System.Collections.Concurrent;

namespace CS_SIEM_PROTOTYP
{
    public class SyslogReceiver : IDataReceiver
    {
        private static ConcurrentQueue<SyslogAnswer> _syslogMessagesQueue = new ConcurrentQueue<SyslogAnswer>();

        // damit man von mehreren Threads strings hinzufuegen kann
        private static int delay = 10;
        private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private static CancellationToken cancellationToken = cancellationTokenSource.Token;
        private static UdpClient udpClient;

        public void ReceiveData()
        {
            throw new NotImplementedException();
        }

        public static void ReceiveSyslogData(int port = 514)
        {
            udpClient = new UdpClient(port);
            Console.WriteLine($"Listening for Syslog messages on port {port}...");

            // rennt in einem anderen Thread und startet jede "delay" sekunden die Methode die die Daten in die Datenbank einfuegen
            Task.Run(() => StartPeriodicDatabaseInsert(delay, cancellationToken), cancellationToken);


            try
            {
                // stoppt wenn cancellation requested wird
                while (!cancellationToken.IsCancellationRequested)
                {
                    IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, port);
                    if (udpClient.Available > 0)
                    {
                        byte[] receivedBytes = udpClient.Receive(ref remoteEndPoint);

                        string syslogMessage = Encoding.UTF8.GetString(receivedBytes);
                        Console.WriteLine($"Received message from {remoteEndPoint.Address}: {syslogMessage}");

                        // syslog nachricht wird and die Queue gegeben
                        SyslogAnswer syslogAnswer =
                            ProcessSyslogMessage(syslogMessage, remoteEndPoint.Address.ToString());
                        
                        _syslogMessagesQueue.Enqueue(syslogAnswer);
                    }
                    else
                    {
                        Thread.Sleep(500);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
            finally
            {
                udpClient.Close();
            }
        }


        private static async Task StartPeriodicDatabaseInsert(int delay, CancellationToken token)
        {
            // stoppt wenn cancellation requested wird
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(1000 * delay, token); // "Delay" sekunden warten und den token ueberpruefen


                InsertMessagesIntoDatabase();
            }
        }

        private static void InsertMessagesIntoDatabase()
        {
            // TODO DATENBANK CODE EINFUEGEN

            Console.WriteLine("Inserting messages into the database...");

            while (!_syslogMessagesQueue.IsEmpty)
            {
                if (_syslogMessagesQueue.TryDequeue(out SyslogAnswer syslogMessage))
                {
                    // Insert syslogMessage into the database
                    Console.WriteLine($"Inserted into database: {syslogMessage}");
                }
            }
        }

        public static void StopReceiver()
        {
            // Tasks stoppen
            cancellationTokenSource.Cancel();

            Console.WriteLine("Shutdown startet...");
        }

        private static SyslogAnswer ProcessSyslogMessage(string syslogMessage, string sourceIP)
        {
            SyslogAnswer syslogAnswer = new SyslogAnswer();
            syslogAnswer.RawMessage = syslogMessage;
            syslogAnswer.SourceIP = sourceIP; // Set the source IP

            // Try to detect and process RFC 5424 (it has a version number after the priority)
            if (syslogMessage.StartsWith("<"))
            {
                int priorityEnd = syslogMessage.IndexOf(">");
                if (priorityEnd > 0 && int.TryParse(syslogMessage.Substring(1, priorityEnd - 1), out int priority))
                {
                    syslogAnswer.Facility = priority / 8; // Facility is the high 8 bits of the priority
                    syslogAnswer.Severity = priority % 8; // Severity is the low 3 bits of the priority

                    // Check if it's RFC 5424 format (it should have a version number)
                    string afterPriority = syslogMessage.Substring(priorityEnd + 1);
                    string[] parts = afterPriority.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    // If the first part after the priority is a number (the version), it's RFC 5424
                    if (parts.Length > 1 && int.TryParse(parts[0], out int version))
                    {
                        // RFC 5424 format
                        syslogAnswer.Timestamp = DateTime.Parse(parts[1]); // Timestamp in ISO8601 format
                        syslogAnswer.Hostname = parts[2]; // Hostname
                        syslogAnswer.Message = string.Join(" ", parts.Skip(6)); // The actual message content
                    }
                    else
                    {
                        // RFC 3164 format
                        string timestampString =
                            afterPriority.Substring(0, 15); // The timestamp is usually 15 characters long
                        syslogAnswer.Timestamp = DateTime.ParseExact(timestampString, "MMM dd HH:mm:ss", null);
                        string remainder = afterPriority.Substring(16).Trim();
                        string[] rfc3164Parts = remainder.Split(' ', 2);
                        syslogAnswer.Hostname = rfc3164Parts[0];
                        syslogAnswer.Message = rfc3164Parts.Length > 1 ? rfc3164Parts[1] : "";
                    }
                }
            }
            else
            {
                // If the message doesn't follow either format, handle it as a raw message
                syslogAnswer.Timestamp = DateTime.Now; // Assume current time for unknown format
                syslogAnswer.Hostname = sourceIP; // Use the source IP as the hostname if the format is unknown
                syslogAnswer.Message = syslogMessage; // Raw message
            }

            return syslogAnswer;
        }

        public static void TestProcessSyslogMessage()
        {
            List<(string Message, string SourceIP)> testData = new List<(string, string)>
            {
                // RFC 3164 example
                ("<34>Oct 18 14:32:16 myhost su: 'su root' failed for user on /dev/pts/2", "192.168.1.50"),

                // RFC 5424 example
                ("<165>1 2024-10-18T14:33:44.003Z myapp.example.com MyApp 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] User login attempt failed",
                    "10.0.0.25"),

                // Firewall log (RFC 3164)
                ("<13>Oct 18 14:35:02 firewall.local kernel: IPTables packet dropped: SRC=192.168.2.10 DST=192.168.1.100 PROTO=TCP SPT=445 DPT=80",
                    "172.16.10.100"),

                // Application log (RFC 3164)
                ("<14>Oct 18 14:36:50 app-server.local myapp: [WARNING] Memory usage exceeded threshold: current usage at 85%",
                    "203.0.113.45"),

                // Non-standard or raw message
                ("This is a raw syslog message without any standard format.", "192.168.0.10")
            };

            // Iterate through test data and process each message
            foreach (var (message, sourceIP) in testData)
            {
                Console.WriteLine("Testing with Syslog Message:");
                Console.WriteLine(message);
                Console.WriteLine("Source IP: " + sourceIP);
                SyslogAnswer result = ProcessSyslogMessage(message, sourceIP);

                Console.WriteLine("Processed Syslog Answer:");
                Console.WriteLine(result);
                Console.WriteLine(new string('-', 50)); // Separator for readability
            }
        }
    }

    public class SyslogConfig
    {
        public int Port { get; set; }
        public string Name { get; set; }
        public int Id { get; set; }

        public override string ToString()
        {
            return $"Port: {Port} id: {Id} name: {Name}";
        }
    }

    public class SyslogAnswer
    {
        public DateTime Timestamp { get; set; }
        public string Hostname { get; set; }
        public string Message { get; set; }
        public int Facility { get; set; }
        public int Severity { get; set; }
        public string SourceIP { get; set; }
        public string RawMessage { get; set; }

        public override string ToString()
        {
            return
                $"[{Timestamp}] {Hostname} (Facility: {Facility}, Severity: {Severity}, Source: {SourceIP}): {Message}";
        }
    }
}


// SYSLOG THREADING https://chatgpt.com/share/670bf4b4-0d3c-8000-be1d-0902162c70e6

// SYSLOG PARSER https://chatgpt.com/share/67127dfc-734c-8000-9982-c6fb46aa62f1