using System.Text.RegularExpressions;
using System.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics;

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
            {
                timestamp = DateTime.Parse(match.Groups["timestamp"].Value),
                duration = new Cassandra.Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                protocol = match.Groups["protocol"].Value,
                srcIP = match.Groups["srcIP"].Value,
                srcPort = int.Parse(match.Groups["srcPort"].Value),
                dstIP = match.Groups["dstIP"].Value,
                dstPort = 0,
                bytes = long.Parse(match.Groups["bytes"].Value),
                packets = int.Parse(match.Groups["packets"].Value),
                flows = int.Parse(match.Groups["flows"].Value),
                typeOfService = int.Parse(match.Groups["typeOfService"].Value.Trim()),
                icmpType = Double.Parse(match.Groups["icmpType"].Value),
                flag = match.Groups["flag"].Value
            };
        }
        else
        {
            Regex r = new Regex(
                @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d+\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<icmpType>\S+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
            Match m = r.Match(line);
            if (m.Success)
            {
                return new NetFlowData
                {
                    timestamp = DateTime.Parse(m.Groups["timestamp"].Value),
                    duration = new Cassandra.Duration(0, 0, parseDurationtoNano(m.Groups["duration"].Value)),
                    protocol = m.Groups["protocol"].Value,
                    srcIP = m.Groups["srcIP"].Value,
                    srcPort = int.Parse(m.Groups["srcPort"].Value),
                    dstIP = m.Groups["dstIP"].Value,
                    dstPort = 0,
                    bytes = long.Parse(m.Groups["bytes"].Value),
                    packets = int.Parse(m.Groups["packets"].Value),
                    flows = int.Parse(m.Groups["flows"].Value),
                    typeOfService = int.Parse(m.Groups["typeOfService"].Value.Trim()),
                    icmpType = Double.Parse(m.Groups["icmpType"].Value),
                    flag = m.Groups["flag"].Value
                };
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
            {
                timestamp = DateTime.Parse(match.Groups["timestamp"].Value),
                duration = new Cassandra.Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                protocol = match.Groups["protocol"].Value,
                srcIP = match.Groups["srcIP"].Value,
                srcPort = int.Parse(match.Groups["srcPort"].Value),
                dstIP = match.Groups["dstIP"].Value,
                dstPort = int.Parse(match.Groups["dstPort"].Value),
                bytes = long.Parse(match.Groups["bytes"].Value),
                packets = int.Parse(match.Groups["packets"].Value),
                flows = int.Parse(match.Groups["flows"].Value),
                typeOfService = int.Parse(match.Groups["typeOfService"].Value.Trim()),
                flag = match.Groups["flag"].Value
            };
        }
        else
        {
            Regex r = new Regex(
                @"(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?<duration>\d+\.\d+) +(?<protocol>\w+) +(?<srcIP>\d+\.\d+\.\d+\.\d+):(?<srcPort>\d+) +-> +(?<dstIP>\d+\.\d+\.\d+\.\d+):(?<dstPort>\d+) +(?<flag>\S+) +(?<typeOfService>\d+) +(?<packets>\d+) +(?<bytes>\d+) +(?<flows>\d+)");
            Match m = r.Match(line);
            if (m.Success)
            {
                return new NetFlowData
                {
                    timestamp = DateTime.Parse(m.Groups["timestamp"].Value),
                    duration = new Cassandra.Duration(0, 0, parseDurationtoNano(match.Groups["duration"].Value)),
                    protocol = m.Groups["protocol"].Value,
                    srcIP = m.Groups["srcIP"].Value,
                    srcPort = int.Parse(m.Groups["srcPort"].Value),
                    dstIP = m.Groups["dstIP"].Value,
                    dstPort = int.Parse(m.Groups["dstPort"].Value),
                    bytes = long.Parse(m.Groups["bytes"].Value),
                    packets = int.Parse(m.Groups["packets"].Value),
                    flows = int.Parse(m.Groups["flows"].Value),
                    typeOfService = int.Parse(m.Groups["typeOfService"].Value.Trim()),
                    flag = m.Groups["flag"].Value
                };
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
            nano += (long) Math.Round(secondsAndMilliseconds * 1_000_000);
        }
        else
        {
            var hours = int.Parse(strarr[0]);
            var minutes = int.Parse(strarr[1]);
            var secondsAndMilliseconds = float.Parse(strarr[2]);
            nano += hours * 60L * 60 * 1_000_000_000;
            nano += minutes * 60L * 1_000_000_000;
            nano += (long) Math.Round(secondsAndMilliseconds * 1_000_000);
        }

        //returns as nanoseconds
        return nano;
    }

    // Method to stop capturing NetFlow data
}

// Class to store NetFlow data
public class NetFlowData
{
    public string srcIP { get; set; }
    public string dstIP { get; set; }
    public int srcPort { get; set; }
    public int dstPort { get; set; }
    public long bytes { get; set; }
    public DateTime timestamp { get; set; }
    public Cassandra.Duration duration { get; set; }
    public string protocol { get; set; }
    public string flag { get; set; }
    public int typeOfService { get; set; }
    public int packets { get; set; }
    public int flows { get; set; }
    public double icmpType { get; set; }


    public override string ToString()
    {
        return $"Source IP: {srcIP}, Destination IP: {dstIP}, Source Port: {srcPort}, Destination Port: {dstPort}, " +
               $"Bytes: {bytes}, Timestamp: {timestamp}, Duration: {duration}, Protocol: {protocol}, " +
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