using CS_DatabaseManager;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CS_SIEM_PROTOTYP
{
    public class SnmpPollScheduler
    {
        private readonly TimeSpan _pollInterval;
        private readonly List<SnmpPollRequest> _snmpRequests;
        private readonly IDatabaseManager _databaseManager;
        private CancellationTokenSource _cancellationTokenSource;

        public SnmpPollScheduler(List<SnmpPollRequest> snmpRequests, IDatabaseManager databaseManager, int delayInSeconds = 10)
        {
            _snmpRequests = snmpRequests;
            _pollInterval = TimeSpan.FromSeconds(delayInSeconds);
            _databaseManager = databaseManager;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task StartPollingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;

            while (!cancellationToken.IsCancellationRequested)
            {
                foreach (var snmpRequest in _snmpRequests)
                {
                    // Poll each SNMP device
                    List<SnmpPoll> snmpPolls = SnmpCustomReceiver.PollSnmpV3(snmpRequest);

                    if (snmpPolls != null && snmpPolls.Count > 0)
                    {
                        // Insert polled data into the database
                        InsertSnmpPollDataAsync(snmpPolls, "SNMP", GetSnmpPollColumn());
                    }
                }

                // Wait for the specified delay or until cancellation is requested
                try
                {
                    await Task.Delay(_pollInterval, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    // Task was canceled, exit gracefully
                    Console.WriteLine("SNMP Polling stopped gracefully.");
                    return;
                }
            }
            Console.WriteLine("SNMPPollScheduler stopped");
        }

        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
            }
        }
        

        public async Task InsertSnmpPollDataAsync(List<SnmpPoll> snmpDatas, string table, Dictionary<string, Type> columns)
        {
            foreach (var snmpData in snmpDatas)
            {
                var data = MapSnmpPollDataToData(snmpData);

                foreach (var value in data)
                {
                    Console.WriteLine(value);
                }

                try
                {
                    await _databaseManager.InsertData(table, columns, data);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to insert data (SNMP POLL SCHEDULER)");
                }
            }
        }

        public Dictionary<string, object> MapSnmpPollDataToData(SnmpPoll snmp)
        {
            return new Dictionary<string, object>
            {
                { "deviceIP", snmp.IpAddress },
                { "hostname", snmp.Hostname },
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
                { "devicePort", typeof(int) },
                { "oid", typeof(string) },
                { "oidValue", typeof(string) },
                { "timestamp", typeof(DateTime) },
                { "UUID", typeof(Guid)} 
            };
        }
    }
    
    
}

// https://chatgpt.com/share/6713a9bf-d594-8000-9eaf-47dbabf9333a