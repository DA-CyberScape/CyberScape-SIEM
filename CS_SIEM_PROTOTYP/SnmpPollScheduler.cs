using CS_DatabaseManager;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cassandra;
using Microsoft.Extensions.Logging;

namespace CS_SIEM_PROTOTYP
{
    public class SnmpPollScheduler
    {
        private readonly int _delay;
        private readonly List<SnmpPollRequest> _snmpRequests;
        private readonly IDatabaseManager _databaseManager;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private readonly ILogger _logger;
        private readonly Dictionary<string, (string ObjectName, string Description)> _oidDictionary;

        public SnmpPollScheduler(List<SnmpPollRequest> snmpRequests, IDatabaseManager databaseManager, ILogger logger,
            Dictionary<string, (string ObjectName, string Description)> oidDictionary,
            int delayInSeconds = 10)
        {
            _snmpRequests = snmpRequests;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _cancellationTokenSource = new CancellationTokenSource();
            _databaseManager.CreateTable("SNMP", GetSnmpPollColumn(), "date, time, UUID", "time DESC, UUID ASC");
            _logger = logger;
            _oidDictionary = oidDictionary;
        }

        public async Task StartPollingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;
            _logger.LogInformation("[INFO] Starting SNMP polling...");

            while (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("[INFO] Beginning new polling cycle.");
                foreach (var snmpRequest in _snmpRequests)
                {
                    // Poll each SNMP device
                    _logger.LogInformation(
                        $"[INFO] Polling SNMP data for device IP: {snmpRequest.IpAddress} on Port: {snmpRequest.Port}");

                    List<SnmpPoll> snmpPolls = SnmpPollGetReceiver.PollSnmpV3(snmpRequest, _oidDictionary);
                    // Console.WriteLine(snmpRequest);

                    // foreach (var poll in snmpPolls)
                        // Console.WriteLine(poll);
                    {
                    }

                    if (snmpPolls != null && snmpPolls.Count > 0)
                    {
                        _logger.LogInformation(
                            $"[INFO] Received {snmpPolls.Count} SNMP poll results for device IP: {snmpRequest.IpAddress}");


                        await InsertSnmpPollDataAsync(snmpPolls, "SNMP", GetSnmpPollColumn());
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        _logger.LogWarning(
                            $"[WARN] No data returned for device IP: {snmpRequest.IpAddress}. Check device connectivity or OID configuration.");
                        Console.ForegroundColor = ConsoleColor.Green;
                    }
                }

                _logger.LogInformation("[INFO] Polling cycle completed. Waiting for next interval...");


                try
                {
                    _logger.LogInformation($"Waiting for {_delay} seconds");
                    await Task.Delay(_delay * 1000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    _logger.LogInformation("SNMP Polling stopped gracefully.");
                    return;
                }
            }

            _logger.LogInformation("SNMP Poll Scheduler stopped.");
        }

        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                Console.ForegroundColor = ConsoleColor.Green;
                _logger.LogInformation("SNMP Poll Scheduler is stopping...");
            }
        }

        //TODO MEHMET austesten DB
        public async Task InsertSnmpPollDataAsync(List<SnmpPoll> snmpDatas, string table,
            Dictionary<string, Type> columns)
        {
            foreach (var snmpData in snmpDatas)
            {
                //Console.WriteLine("INSERTING SNMP POLL:");
                //Console.WriteLine(snmpData);
                if (snmpData.Oid.Equals("1.3.6.1.4.1.12356.101.7.2.2.1.1.5"))
                {
                    // Console.WriteLine("THIS OID IS GETTING INSERTED FORTIGATE STUFF");
                    _logger.LogWarning("THE OID IS GETTING INSERTED");
                }


                var data = MapSnmpPollDataToData(snmpData);


                try
                {
                    await _databaseManager.InsertData(table, columns, data);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to insert data (SNMP POLL SCHEDULER)");
                }
                // Console.WriteLine("SUCCESSFULLY INSERTED SNMP POLL");
            }
        }

        public Dictionary<string, object> MapSnmpPollDataToData(SnmpPoll snmp)
        {
            return new Dictionary<string, object>
            {
                { "deviceIP", snmp.IpAddress },
                { "hostname", snmp.Hostname },
                { "oid_name", snmp.Name },
                { "oid", snmp.Oid },
                { "oidValue", snmp.OidValue },
                { "time", snmp.Time },
                { "date", snmp.Date },
                { "UUID", Guid.NewGuid() }
            };
        }

        public Dictionary<string, Type> GetSnmpPollColumn()
        {
            return new Dictionary<string, Type>
            {
                { "deviceIP", typeof(string) },
                { "hostname", typeof(string) },
                { "oid_name", typeof(string) },
                { "oid", typeof(string) },
                { "oidValue", typeof(string) },
                { "time", typeof(LocalTime) },
                { "UUID", typeof(Guid) },
                { "date", typeof(LocalDate) }
            };
        }
    }
}

// https://chatgpt.com/share/6713a9bf-d594-8000-9eaf-47dbabf9333a