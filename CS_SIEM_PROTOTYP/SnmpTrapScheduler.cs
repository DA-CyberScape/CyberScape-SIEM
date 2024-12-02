using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP
{
    public class SnmpTrapScheduler
    {
        private readonly int _delay;
        private readonly List<SnmpTrapConfig> _snmpTrapConfigs;
        private readonly IDatabaseManager _databaseManager;
        private readonly List<SnmpTrapReceiver> _snmpTrapReceivers;
        private readonly List<Task> _snmpTrapTasks;
        private CancellationTokenSource _cancellationTokenSource;

        public SnmpTrapScheduler(List<SnmpTrapConfig> snmpTrapConfigs, IDatabaseManager databaseManager,
            int delayInSeconds = 10)
        {
            _snmpTrapConfigs = snmpTrapConfigs;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _snmpTrapReceivers = new List<SnmpTrapReceiver>();
            _snmpTrapTasks = new List<Task>();
            _cancellationTokenSource = new CancellationTokenSource();
        }


        public async Task StartAnalyzingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;

            Console.WriteLine("[INFO] Starting SNMPTrapScheduler Scheduler...");


            foreach (var config in _snmpTrapConfigs)
            {
                Console.WriteLine(config);
                var snmpTrapReceiver = new SnmpTrapReceiver(_databaseManager, config.Port, _delay);
                _snmpTrapReceivers.Add(snmpTrapReceiver);
                


                var task = Task.Run(() => snmpTrapReceiver.StartListening(), cancellationToken);
                _snmpTrapTasks.Add(task);

                Console.WriteLine($"[INFO] SnmpTRAPSCHEDULER '{config.Name}' started listening on port {config.Port}.");
            }


            await Task.WhenAll(_snmpTrapTasks);

            Console.WriteLine("[INFO] SNMP Trap Scheduler has stopped all receivers.");
        }

        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel(); // Signal cancellation for all receivers
                Console.WriteLine("[INFO] Stopping all SNMP Trap Receivers...");

                // Stop each receiver and log confirmation
                foreach (var receiver in _snmpTrapReceivers)
                {
                    receiver.StopReceiver();
                }

                Task.WaitAll(_snmpTrapTasks.ToArray()); // Ensure all tasks have stopped
                Console.WriteLine("[INFO] All SNMP Trap Receivers have been stopped.");
            }
        }
    }
}