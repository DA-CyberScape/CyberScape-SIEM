using CS_DatabaseManager;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CS_SIEM_PROTOTYP
{
    public class SnmpPollScheduler
    {
        private readonly int _delay;
        private readonly List<SnmpPollRequest> _snmpRequests;
        private readonly IDatabaseManager _databaseManager;
        private CancellationTokenSource _cancellationTokenSource;
        private ILogger _logger;

        public SnmpPollScheduler(List<SnmpPollRequest> snmpRequests, IDatabaseManager databaseManager, ILogger logger,
            int delayInSeconds = 10)
        {
            _snmpRequests = snmpRequests;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _cancellationTokenSource = new CancellationTokenSource();
            _databaseManager.CreateTable("SNMP", GetSnmpPollColumn(), "UUID, timestamp");
            _logger = logger;
        }

        public async Task StartPollingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;
            Console.ForegroundColor = ConsoleColor.Green;
            _logger.LogInformation("[INFO] Starting SNMP polling...");

            while (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("[INFO] Beginning new polling cycle.");
                foreach (var snmpRequest in _snmpRequests)
                {
                    // Poll each SNMP device
                    _logger.LogInformation(
                        $"[INFO] Polling SNMP data for device IP: {snmpRequest.IpAddress} on Port: {snmpRequest.Port}");

                    List<SnmpPoll> snmpPolls = SnmpCustomReceiver.PollSnmpV3(snmpRequest);
                    // Console.WriteLine(snmpRequest);

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
                var data = MapSnmpPollDataToData(snmpData);

                // foreach (var value in data)
                // {
                //     Console.WriteLine(value);
                // }

                try
                {
                    // Console.WriteLine("Starting with SNMP Insert");
                    await _databaseManager.InsertData(table, columns, data);
                    // Console.WriteLine("Ending with SNMP Insert");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to insert data (SNMP POLL SCHEDULER)");
                }
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
                { "timestamp", snmp.Timestamp },
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
                { "timestamp", typeof(DateTime) },
                { "UUID", typeof(Guid) }
            };
        }
    }
}

// https://chatgpt.com/share/6713a9bf-d594-8000-9eaf-47dbabf9333a