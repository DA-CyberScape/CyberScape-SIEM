using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Timers;
using System.Collections.Concurrent;

namespace CS_SIEM_PROTOTYP
{
    public class SyslogReceiver : IDataReceiver
    {
        private static ConcurrentQueue<string> _syslogMessagesQueue = new ConcurrentQueue<string>();
        // damit man von mehreren Threads strings hinzufuegen kann
        private static bool isReceiving = true;
        private static int delay = 10;
        private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private static CancellationToken cancellationToken = cancellationTokenSource.Token;
        private static UdpClient udpClient;

        public void ReceiveData()
        {
            throw new NotImplementedException();
        }

        public static void ReceiveSyslogData(int port)
        {
            if (port == 0)
            {
                port = 514;
            }

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
                        _syslogMessagesQueue.Enqueue(syslogMessage);
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
                await Task.Delay(1000 * delay); // Wait for 10 seconds

                InsertMessagesIntoDatabase();
            }
        }

        private static void InsertMessagesIntoDatabase()
        {
           
            // TODO DATENBANK CODE EINFUEGEN

            Console.WriteLine("Inserting messages into the database...");

            while (!_syslogMessagesQueue.IsEmpty)
            {
                if (_syslogMessagesQueue.TryDequeue(out string syslogMessage))
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
}
