using System.Text.RegularExpressions;
using System.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Cassandra;

namespace CS_SIEM_PROTOTYP;

using CS_DatabaseManager;

public class NetflowReceiver : IDataReceiver
{
    public void ReceiveData()
    {
        throw new NotImplementedException();
    }

    private readonly IDatabaseManager _databaseManager;

    public NetflowReceiver(IDatabaseManager databaseManager)
    {
        _databaseManager = databaseManager;
    }

    public static void StartCapturingNetFlowData(string nfcapdPath, string captureDir)
    {
        bool isProcessRunning = Process.GetProcessesByName("nfcapd").Any();

        if (isProcessRunning)
        {
            //Console.WriteLine("NetFlow capturing is already running.");
            return;
        }

        Process nfcapdProcess = new Process();
        nfcapdProcess.StartInfo.FileName = nfcapdPath;
        nfcapdProcess.StartInfo.Arguments = $"-l {captureDir} -w -D -p 2055";
        nfcapdProcess.StartInfo.RedirectStandardOutput = true;
        nfcapdProcess.StartInfo.UseShellExecute = false;
        nfcapdProcess.Start();

        //Console.WriteLine("Started capturing NetFlow data...");
    }

    public static string[] GetFilePaths(string folderPath)
    {
        if (!Directory.Exists(folderPath))
        {
            Console.WriteLine("The specified folder does not exist.");
            return null;
        }

        string[] files = Directory.GetFiles(folderPath, "nfcapd.2*");

        return files;
    }

    // Method to monitor the capture directory for new files


    // Method to process a captured file using nfdump
    public static List<string> ProcessCapturedFile(string filePath, string nfdumpPath)
    {
        Process nfdumpProcess = new Process();
        nfdumpProcess.StartInfo.FileName = nfdumpPath;
        nfdumpProcess.StartInfo.Arguments = $"-r {filePath} -o long";
        nfdumpProcess.StartInfo.RedirectStandardOutput = true;
        nfdumpProcess.StartInfo.UseShellExecute = false;
        nfdumpProcess.Start();

        string output = nfdumpProcess.StandardOutput.ReadToEnd();
        nfdumpProcess.WaitForExit();


        List<string> lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();


        if (lines.Count > 5)
        {
            lines = lines.Skip(1).Take(lines.Count - 5).ToList();
        }
        else
        {
            lines = new List<string>();
        }

        return lines;
        // ParseNetFlowData(output);
    }

    // Method to parse nfdump output into NetFlowData objects
    public static List<NetFlowData> ParseNetFlowData(List<string> lines)
    {
        List<NetFlowData> result = new List<NetFlowData>();

        foreach (var line in lines)
        {
            try
            {
                if (!line.Contains("ICMP"))
                {
                    result.Add(ParseLineToNetFlowData(line));
                }
                else
                {
                    result.Add(ParseICMPLineToNetFlowData(line));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        return result;
    }

    // Method to parse a single line of nfdump output
    public static NetFlowData ParseICMPLineToNetFlowData(string line)
    {
        Regex regex = new Regex(
            @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d{2}:\d{2}:\d{2}\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<icmpType>\S+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
        Match match = regex.Match(line);


        if (match.Success)
        {
            return new NetFlowData
            (
                DateTime.Parse(match.Groups["timestamp"].Value),
                new Cassandra.Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                match.Groups["protocol"].Value,
                match.Groups["srcIP"].Value,
                int.Parse(match.Groups["srcPort"].Value),
                match.Groups["dstIP"].Value,
                0,
                long.Parse(match.Groups["bytes"].Value),
                int.Parse(match.Groups["packets"].Value),
                int.Parse(match.Groups["flows"].Value),
                int.Parse(match.Groups["typeOfService"].Value.Trim()),
                Double.Parse(match.Groups["icmpType"].Value),
                match.Groups["flag"].Value
            );
        }
        else
        {
            Regex r = new Regex(
                @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d+\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<icmpType>\S+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
            Match m = r.Match(line);
            if (m.Success)
            {
                return new NetFlowData
                (
                    DateTime.Parse(m.Groups["timestamp"].Value),
                    new Cassandra.Duration(0, 0, parseDurationtoNano(m.Groups["duration"].Value)),
                    m.Groups["protocol"].Value,
                    m.Groups["srcIP"].Value,
                    int.Parse(m.Groups["srcPort"].Value),
                    m.Groups["dstIP"].Value,
                    0,
                    long.Parse(m.Groups["bytes"].Value),
                    int.Parse(m.Groups["packets"].Value),
                    int.Parse(m.Groups["flows"].Value),
                    int.Parse(m.Groups["typeOfService"].Value.Trim()),
                    Double.Parse(m.Groups["icmpType"].Value),
                    m.Groups["flag"].Value
                );
            }
        }


        return null;
    }

    public static NetFlowData ParseLineToNetFlowData(string line)
    {
        // Regex example to match nfdump output (you may need to adjust based on your format)
        Regex regex = new Regex(
            @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d{2}:\d{2}:\d{2}\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<dstPort>\d+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
        Match match = regex.Match(line);
        //Console.WriteLine(line);

        if (match.Success)
        {
            return new NetFlowData
            (
                DateTime.Parse(match.Groups["timestamp"].Value),
                new Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                match.Groups["protocol"].Value,
                match.Groups["srcIP"].Value,
                int.Parse(match.Groups["srcPort"].Value),
                match.Groups["dstIP"].Value,
                int.Parse(match.Groups["dstPort"].Value),
                long.Parse(match.Groups["bytes"].Value),
                int.Parse(match.Groups["packets"].Value),
                int.Parse(match.Groups["flows"].Value),
                int.Parse(match.Groups["typeOfService"].Value.Trim()),
                match.Groups["flag"].Value
            );
        }
        else
        {
            Regex r = new Regex(
                @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d+\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<dstPort>\d+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
            Match m = r.Match(line);
            if (m.Success)
            {
                return new NetFlowData
                (
                    DateTime.Parse(m.Groups["timestamp"].Value),
                    new Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                    m.Groups["protocol"].Value,
                    m.Groups["srcIP"].Value,
                    int.Parse(m.Groups["srcPort"].Value),
                    m.Groups["dstIP"].Value,
                    int.Parse(m.Groups["dstPort"].Value),
                    long.Parse(m.Groups["bytes"].Value),
                    int.Parse(m.Groups["packets"].Value),
                    int.Parse(m.Groups["flows"].Value),
                    int.Parse(m.Groups["typeOfService"].Value.Trim()),
                    m.Groups["flag"].Value
                );
            }
        }

        return null;
    }

    private static long parseDurationtoNano(string duration)
    {
        // read Format 00:00:00.000 or 00.000
        long nano = 0; // nano = 10^-9 seconds
        String[] strarr = duration.Split(':');

        if (strarr.Length == 1)
        {
            var secondsAndMilliseconds = float.Parse(strarr[0]);
            nano += (long)Math.Round(secondsAndMilliseconds * 1_000_000);
        }
        else
        {
            var hours = int.Parse(strarr[0]);
            var minutes = int.Parse(strarr[1]);
            var secondsAndMilliseconds = float.Parse(strarr[2]);
            nano += hours * 60L * 60 * 1_000_000_000;
            nano += minutes * 60L * 1_000_000_000;
            nano += (long)Math.Round(secondsAndMilliseconds * 1_000_000);
        }

        //returns as nanoseconds
        return nano;
    }

    // Method to stop capturing NetFlow data
}

// Class to store NetFlow data
public class NetFlowData
{
    public NetFlowData(DateTime timestamp, Duration drtn, string prot, string sIp, int sPort, string dIp,
        int dPort, long b, int pckts, int f, int tos, double icmpT, string flg)
    {
        time = new LocalTime(timestamp.Hour, timestamp.Minute, timestamp.Second, timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000);
        date = new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day);
        duration = drtn;
        protocol = prot;
        srcIP = sIp;
        srcPort = sPort;
        dstIP = dIp;
        dstPort = dPort;
        bytes = b;
        packets = pckts;
        flows = f;
        typeOfService = tos;
        icmpType = icmpT;
        flag = flg;
    }

    public NetFlowData(DateTime timestamp, Duration drtn, string prot, string sIp, int sPort, string dIp,
        int dPort, long b, int pckts, int f, int tos, string flg)
    {
        time = new LocalTime(timestamp.Hour, timestamp.Minute, timestamp.Second, timestamp.Millisecond * 1000000 + timestamp.Microsecond * 1000);
        date = new LocalDate(timestamp.Year, timestamp.Month, timestamp.Day);
        duration = drtn;
        protocol = prot;
        srcIP = sIp;
        srcPort = sPort;
        dstIP = dIp;
        dstPort = dPort;
        bytes = b;
        packets = pckts;
        flows = f;
        typeOfService = tos;
        flag = flg;
    }

    public string srcIP { get; set; }
    public string dstIP { get; set; }
    public int srcPort { get; set; }
    public int dstPort { get; set; }
    public long bytes { get; set; }
    public LocalDate date { get; set; }
    public LocalTime time { get; set; }
    public Duration duration { get; set; }
    public string protocol { get; set; }
    public string flag { get; set; }
    public int typeOfService { get; set; }
    public int packets { get; set; }
    public int flows { get; set; }
    public double icmpType { get; set; }


    public override string ToString()
    {
        return $"Source IP: {srcIP}, Destination IP: {dstIP}, Source Port: {srcPort}, Destination Port: {dstPort}, " +
               $"Bytes: {bytes}, Date: {date}, Time: {time}, Duration: {duration}, Protocol: {protocol}, " +
               $"Flag: {flag}, Type of Service: {typeOfService}, Packets: {packets}, Flows: {flows}, ICMPType: {icmpType}";
    }
}

public class NfConfig
{
    public string FolderLocation { get; set; }
    public string NfdumpBinaryLocation { get; set; }
    public string NfcapdBinaryLocation { get; set; }
    public long Port { get; set; }
    public string Name { get; set; }
    public int Id { get; set; }

    public override string ToString()
    {
        return $"Folder Location: {FolderLocation}, " +
               $"Nfdump Binary Location: {NfdumpBinaryLocation}, " +
               $"Nfcapd Binary Location: {NfcapdBinaryLocation}, " +
               $"Port: {Port}  id: {Id} name: {Name}";
    }
}