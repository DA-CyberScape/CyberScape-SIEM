using CS_DatabaseManager;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CS_SIEM_PROTOTYP
{
    public class SnmpPollScheduler
    {
        private readonly int _delay;
        private readonly List<SnmpPollRequest> _snmpRequests;
        private readonly IDatabaseManager _databaseManager;
        private CancellationTokenSource _cancellationTokenSource;

        public SnmpPollScheduler(List<SnmpPollRequest> snmpRequests, IDatabaseManager databaseManager, int delayInSeconds = 10)
        {
            _snmpRequests = snmpRequests;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task StartPollingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;
            Console.WriteLine("[INFO] Starting SNMP polling...");

            while (!cancellationToken.IsCancellationRequested)
            {
                Console.WriteLine("[INFO] Beginning new polling cycle.");
                foreach (var snmpRequest in _snmpRequests)
                {
                    // Poll each SNMP device
                    Console.WriteLine($"[INFO] Polling SNMP data for device IP: {snmpRequest.IpAddress} on Port: {snmpRequest.Port}");

                    List<SnmpPoll> snmpPolls = SnmpCustomReceiver.PollSnmpV3(snmpRequest);

                    if (snmpPolls != null && snmpPolls.Count > 0)
                    {
       
                        Console.WriteLine($"[INFO] Received {snmpPolls.Count} SNMP poll results for device IP: {snmpRequest.IpAddress}");
                        
                        //TODO DATABASE
                        // InsertSnmpPollDataAsync(snmpPolls, "SNMP", GetSnmpPollColumn());
                    }else
                    {
                        Console.WriteLine($"[WARN] No data returned for device IP: {snmpRequest.IpAddress}. Check device connectivity or OID configuration.");
                    }
                }
                Console.WriteLine("[INFO] Polling cycle completed. Waiting for next interval...");


               
                try
                {
                    await Task.Delay(_delay * 1000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    
                    Console.WriteLine("[INFO] SNMP Polling stopped gracefully.");
                    return;
                }
            }
            Console.WriteLine("[INFO] SNMP Poll Scheduler stopped.");
        }

        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                Console.WriteLine("[INFO] SNMP Poll Scheduler is stopping...");
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