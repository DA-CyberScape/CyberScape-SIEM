using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP
{
    public class SyslogReceiver : IDataReceiver
    {
        private static ConcurrentQueue<SyslogAnswer> _syslogMessagesQueue = new ConcurrentQueue<SyslogAnswer>();
        private static int _delay = 10;
        private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private static CancellationToken cancellationToken = cancellationTokenSource.Token;
        private static UdpClient udpClient;
        private IDatabaseManager _db;
        private int _port;

        public void ReceiveData()
        {
            throw new NotImplementedException();
        }

        public SyslogReceiver(IDatabaseManager db, int port, int delay = 10)
        {
            _db = db;
            _delay = delay;
            _port = port;
        }



        public void ReceiveSyslogData()
        {
            udpClient = new UdpClient(_port);
            Console.WriteLine($"[INFO] Syslog Receiver is listening on port {_port}...");

            Task.Run(() => StartPeriodicDatabaseInsert(_delay, cancellationToken), cancellationToken);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    // listenting part
                    IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, _port);

                    if (udpClient.Available > 0)
                    {
                        byte[] receivedBytes = udpClient.Receive(ref remoteEndPoint);
                        string syslogMessage = Encoding.UTF8.GetString(receivedBytes);

                        SyslogAnswer syslogAnswer = ProcessSyslogMessage(syslogMessage, remoteEndPoint.Address.ToString());
                        _syslogMessagesQueue.Enqueue(syslogAnswer);
                    }
                    else
                    {
                        Thread.Sleep(500);
                    }
                    // listenting part
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[ERROR] An error occurred: {e.Message}");
            }
            finally
            {
                udpClient.Close();
                Console.WriteLine("[INFO] Syslog Receiver has stopped listening.");
            }
        }

        private async Task StartPeriodicDatabaseInsert(int delay, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(1000 * delay, token);
                InsertMessagesIntoDatabase();
            }
        }

        private void InsertMessagesIntoDatabase()
        {
            while (!_syslogMessagesQueue.IsEmpty)
            {
                if (_syslogMessagesQueue.TryDequeue(out SyslogAnswer syslogMessage))
                {
                    if (syslogMessage.Message.Length > 0)
                    {
                        Console.WriteLine($"[INFO] Inserted message from {syslogMessage.Hostname} into database.");
                        Console.WriteLine(syslogMessage.Facility);
                        Console.WriteLine(syslogMessage.Severity);
                        Console.WriteLine(syslogMessage.Hostname);
                        Console.WriteLine(syslogMessage.Timestamp);
                        Console.WriteLine(syslogMessage.Message);
                        
                        // TODO: MEHMET DB LOGIK
                    }

                    
                }
            }
        }

        public void StopReceiver()
        {
            cancellationTokenSource.Cancel();
            Console.WriteLine("[INFO] Syslog Receiver shutdown initiated...");
        }

        private static SyslogAnswer ProcessSyslogMessage(string syslogMessage, string sourceIP)
        {
            SyslogAnswer syslogAnswer = new SyslogAnswer
            {
                RawMessage = syslogMessage,
                SourceIP = sourceIP
            };
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
                            syslogAnswer.Timestamp = DateTime.Parse(parts[1]);
                            syslogAnswer.Hostname = parts[2];
                            syslogAnswer.Message = string.Join(" ", parts.Skip(6));
                        }
                        else
                        {
                            string timestampString = afterPriority.Substring(0, 15);
                            syslogAnswer.Timestamp = DateTime.ParseExact(timestampString, "MMM dd HH:mm:ss", null);
                            string[] rfc3164Parts = afterPriority.Substring(16).Trim().Split(' ', 2);
                            syslogAnswer.Hostname = rfc3164Parts[0];
                            syslogAnswer.Message = rfc3164Parts.Length > 1 ? rfc3164Parts[1] : "";
                        }
                    }
                }
                else
                {
                    syslogAnswer.Timestamp = DateTime.Now;
                    syslogAnswer.Hostname = sourceIP;
                    syslogAnswer.Message = syslogMessage;
                }
            }
            catch
            {
                syslogAnswer.Timestamp = DateTime.Now;
                syslogAnswer.Hostname = sourceIP;
                syslogAnswer.Message = syslogMessage;
            }


            

            return syslogAnswer;
        }

        public static void TestProcessSyslogMessage()
        {
            List<(string Message, string SourceIP)> testData = new List<(string, string)>
            {
                ("<34>Oct 18 14:32:16 myhost su: 'su root' failed for user on /dev/pts/2", "192.168.1.50"),
                ("<165>1 2024-10-18T14:33:44.003Z myapp.example.com MyApp 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] User login attempt failed", "10.0.0.25"),
                ("<13>Oct 18 14:35:02 firewall.local kernel: IPTables packet dropped: SRC=192.168.2.10 DST=192.168.1.100 PROTO=TCP SPT=445 DPT=80", "172.16.10.100"),
                ("<14>Oct 18 14:36:50 app-server.local myapp: [WARNING] Memory usage exceeded threshold: current usage at 85%", "203.0.113.45"),
                ("This is a raw syslog message without any standard format.", "192.168.0.10")
            };

            foreach (var (message, sourceIP) in testData)
            {
                Console.WriteLine("[TEST] Processing Syslog Message:");
                SyslogAnswer result = ProcessSyslogMessage(message, sourceIP);
                Console.WriteLine(result);
                Console.WriteLine(new string('-', 50));
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
            return $"Port: {Port}, Id: {Id}, Name: {Name}";
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
            return $"[{Timestamp}] {Hostname} (Facility: {Facility}, Severity: {Severity}, Source: {SourceIP}): {Message}";
        }
    }
}
