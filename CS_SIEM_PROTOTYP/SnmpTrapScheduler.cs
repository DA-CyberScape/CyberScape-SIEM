using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;

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
        private ILogger _logger;

        public SnmpTrapScheduler(List<SnmpTrapConfig> snmpTrapConfigs, IDatabaseManager databaseManager,
            ILogger logger,
            int delayInSeconds = 10)
        {
            _snmpTrapConfigs = snmpTrapConfigs;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _snmpTrapReceivers = new List<SnmpTrapReceiver>();
            _snmpTrapTasks = new List<Task>();
            _cancellationTokenSource = new CancellationTokenSource();
            _logger = logger;
        }


        public async Task StartAnalyzingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;

            _logger.LogInformation("[INFO] Starting SNMPTrapScheduler Scheduler...");


            foreach (var config in _snmpTrapConfigs)
            {
                _logger.LogInformation($"{config}");
                var snmpTrapReceiver = new SnmpTrapReceiver(_databaseManager, _logger, config.Port, _delay);
                _snmpTrapReceivers.Add(snmpTrapReceiver);
                


                var task = Task.Run(() => snmpTrapReceiver.StartListening(), cancellationToken);
                _snmpTrapTasks.Add(task);

                _logger.LogInformation($"[INFO] SnmpTRAPSCHEDULER '{config.Name}' started listening on port {config.Port}.");
            }


            await Task.WhenAll(_snmpTrapTasks);

            _logger.LogInformation("[INFO] SNMP Trap Scheduler has stopped all receivers.");
        }

        public void StopPolling()
        {
            _logger.LogDebug($"SNMP Trap Stop Polling Cancellation Token: {_cancellationTokenSource.IsCancellationRequested}");
            if (!_cancellationTokenSource.IsCancellationRequested)
            {
                Console.WriteLine("INSIDE TRAP RECEIVER STOP FUNCTION 1 ");
                _cancellationTokenSource.Cancel(); // Signal cancellation for all receivers
                _logger.LogInformation("[INFO] Stopping all SNMP Trap Receivers...");
                Console.WriteLine("INSIDE TRAP RECEIVER STOP FUNCTION 2");
                // Stop each receiver and log confirmation
                foreach (var receiver in _snmpTrapReceivers)
                {
                    receiver.StopReceiver();
                    Console.WriteLine("INSIDE TRAP RECEIVER STOP FUNCTION 3");
                }
                Console.WriteLine("INSIDE TRAP RECEIVER STOP FUNCTION 4 ");

                
                // Task.WaitAll(_snmpTrapTasks.ToArray()); // Ensure all tasks have stopped
                Console.WriteLine("INSIDE TRAP RECEIVER STOP FUNCTION 5 ");
                _logger.LogInformation("[INFO] All SNMP Trap Receivers have been stopped. [INSIDE SCHEDULER]");
            }
        }
    }
}