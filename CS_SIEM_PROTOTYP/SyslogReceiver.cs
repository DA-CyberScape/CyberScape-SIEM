using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CS_SIEM_PROTOTYP;

public class SyslogReceiver : IDataReceiver
{
    public void ReceiveData()
    {
        throw new NotImplementedException();
    }


    public static void ReceiveSyslogData(int port)
    {
        UdpClient udpClient = new UdpClient(port);

        Console.WriteLine($"Listening for Syslog messages on port {port}...");

        try
        {
            // Continuously listen for incoming syslog messages
            while (true)
            {
                // Receive the syslog message from any device
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, port);
                byte[] receivedBytes = udpClient.Receive(ref remoteEndPoint);

                // Convert the received bytes into a readable string (UTF-8 encoding)
                string syslogMessage = Encoding.UTF8.GetString(receivedBytes);

                // Output the received syslog message
                Console.WriteLine($"Received message from {remoteEndPoint.Address}: {syslogMessage}");
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

}