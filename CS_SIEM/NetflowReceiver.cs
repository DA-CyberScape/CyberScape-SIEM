using System.Diagnostics;
using System.Text.RegularExpressions;
using CS_DatabaseManager;
using Cassandra;
namespace CS_SIEM;

/// <summary>
/// Class responsible for receiving and processing NetFlow data.
/// </summary>
public class NetflowReceiver
{


    private readonly IDatabaseManager _databaseManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="NetflowReceiver"/> class.
    /// </summary>
    /// <param name="databaseManager">Instance of <see cref="IDatabaseManager"/> for database operations.</param>
    public NetflowReceiver(IDatabaseManager databaseManager)
    {
        _databaseManager = databaseManager;
    }

    

    /// <summary>
    /// Retrieves file paths from the specified folder that match the pattern "nfcapd.2*".
    /// </summary>
    /// <param name="folderPath">Path of the folder to search for files.</param>
    /// <returns>Array of file paths if found, otherwise null.</returns>
    public static string[]? GetFilePaths(string folderPath)
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
    /// <summary>
    /// Processes a captured NetFlow file using nfdump.
    /// </summary>
    /// <param name="filePath">Path of the captured file.</param>
    /// <param name="nfdumpPath">Path of the nfdump binary.</param>
    /// <returns>List of processed NetFlow data lines.</returns>
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

    /// <summary>
    /// Parses nfdump output into a list of <see cref="NetFlowData"/> objects.
    /// </summary>
    /// <param name="lines">List of nfdump output lines.</param>
    /// <returns>List of parsed <see cref="NetFlowData"/> objects.</returns>
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
                
                // Console.WriteLine(e);
            }
        }

        return result;
    }

    /// <summary>
    /// Parses a single ICMP-related NetFlow line into a <see cref="NetFlowData"/> object.
    /// </summary>
    /// <param name="line">A single line from nfdump output.</param>
    /// <returns>Parsed <see cref="NetFlowData"/> object.</returns>
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
    /// <summary>
    /// Parses a non-ICMP NetFlow line into a <see cref="NetFlowData"/> object.
    /// </summary>
    /// <param name="line">A single line from nfdump output.</param>
    /// <returns>Parsed <see cref="NetFlowData"/> object.</returns>

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

    /// <summary>
    /// Converts duration string to nanoseconds.
    /// </summary>
    /// <param name="duration">Duration string in format 00:00:00.000 or 00.000.</param>
    /// <returns>Duration in nanoseconds.</returns>
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

/// <summary>
/// Represents NetFlow data.
/// </summary>
public class NetFlowData
{
    /// <summary>
    /// Initializes NetflowData class
    /// </summary>
    /// <param name="timestamp">when the flow happend</param>
    /// <param name="drtn">duraction of the flow</param>
    /// <param name="prot">protocol used</param>
    /// <param name="sIp">source ip</param>
    /// <param name="sPort">source port</param>
    /// <param name="dIp">destination ip</param>
    /// <param name="dPort">destination port</param>
    /// <param name="b">number of bytes</param>
    /// <param name="pckts">number of packets</param>
    /// <param name="f">number of flows</param>
    /// <param name="tos">type of servce</param>
    /// <param name="icmpT">icmp type</param>
    /// <param name="flg">flag</param>
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

    /// <summary>
    ///
    /// </summary>
    /// <param name="timestamp">when the flow happend</param>
    /// <param name="drtn">duraction of the flow</param>
    /// <param name="prot">protocol used</param>
    /// <param name="sIp">source ip</param>
    /// <param name="sPort">source port</param>
    /// <param name="dIp">destination ip</param>
    /// <param name="dPort">destination port</param>
    /// <param name="b">number of bytes</param>
    /// <param name="pckts">number of packets</param>
    /// <param name="f">number of flows</param>
    /// <param name="tos">type of servce</param>
    /// <param name="flg">flag</param>
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

    /// <summary>
    /// Gets or sets the source ip.
    /// </summary>
    public string srcIP { get; set; }
    /// <summary>
    /// Gets or sets the destination ip.
    /// </summary>
    public string dstIP { get; set; }
    /// <summary>
    /// Gets or sets the source port.
    /// </summary>

    public int srcPort { get; set; }
    /// <summary>
    /// Gets or sets the destination port.
    /// </summary>
    public int dstPort { get; set; }
    /// <summary>
    /// Gets or sets the bytes.
    /// </summary>
    public long bytes { get; set; }
    /// <summary>
    /// Gets or sets the date.
    /// </summary>
    public LocalDate date { get; set; }
    /// <summary>
    /// Gets or sets the time.
    /// </summary>
    public LocalTime time { get; set; }
    /// <summary>
    /// Gets or sets the duration.
    /// </summary>
    public Duration duration { get; set; }
    /// <summary>
    /// Gets or sets the protocol.
    /// </summary>
    public string protocol { get; set; }
    /// <summary>
    /// Gets or sets the flag.
    /// </summary>
    public string flag { get; set; }
    /// <summary>
    /// Gets or sets the typeOfService.
    /// </summary>
    public int typeOfService { get; set; }
    /// <summary>
    /// Gets or sets the packets.
    /// </summary>
    public int packets { get; set; }
    /// <summary>
    /// Gets or sets the flows.
    /// </summary>
    public int flows { get; set; }
    /// <summary>
    /// Gets or sets the icmpType.
    /// </summary>
    public double icmpType { get; set; }



    /// <summary>
    /// overrides the toString method
    /// </summary>
    /// <returns>all the information in a string</returns>
    public override string ToString()
    {
        return $"Source IP: {srcIP}, Destination IP: {dstIP}, Source Port: {srcPort}, Destination Port: {dstPort}, " +
               $"Bytes: {bytes}, Date: {date}, Time: {time}, Duration: {duration}, Protocol: {protocol}, " +
               $"Flag: {flag}, Type of Service: {typeOfService}, Packets: {packets}, Flows: {flows}, ICMPType: {icmpType}";
    }
}

/// <summary>
/// Configuration class for NetFlow settings.
/// </summary>
public class NfConfig
{
    /// <summary>
    /// Gets or sets the FolderLocation.
    /// </summary>
    public string FolderLocation { get; set; }
    /// <summary>
    /// Gets or sets the NfdumpBinaryLocation.
    /// </summary>
    public string NfdumpBinaryLocation { get; set; }
    /// <summary>
    /// Gets or sets the NfcapdBinaryLocation.
    /// </summary>
    public string NfcapdBinaryLocation { get; set; }
    /// <summary>
    /// Gets or sets the Port.
    /// </summary>
    public long Port { get; set; }
    /// <summary>
    /// Gets or sets the Name.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// Gets or sets the Id.
    /// </summary>
    public int Id { get; set; }



    /// <summary>
    /// overrides the toString method
    /// </summary>
    /// <returns>all the information in a string</returns>
    public override string ToString()
    {
        return $"Folder Location: {FolderLocation}, " +
               $"Nfdump Binary Location: {NfdumpBinaryLocation}, " +
               $"Nfcapd Binary Location: {NfcapdBinaryLocation}, " +
               $"Port: {Port}  id: {Id} name: {Name}";
    }
}