using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP
{
    public class SyslogScheduler
    {
        private readonly int _delay;
        private readonly List<SyslogConfig> _syslogConfigs;
        private readonly IDatabaseManager _databaseManager;
        private readonly List<SyslogReceiver> _syslogReceivers;
        private readonly List<Task> _syslogTasks;
        private CancellationTokenSource _cancellationTokenSource;

        public SyslogScheduler(List<SyslogConfig> syslogConfigs, IDatabaseManager databaseManager, int delayInSeconds = 10)
        {
            _syslogConfigs = syslogConfigs;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _syslogReceivers = new List<SyslogReceiver>();
            _syslogTasks = new List<Task>();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        
        public async Task StartAnalyzingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;

            Console.WriteLine("[INFO] Starting Syslog Scheduler...");

            
            foreach (var config in _syslogConfigs)
            {
                var syslogReceiver = new SyslogReceiver(_databaseManager, config.Port,_delay);
                _syslogReceivers.Add(syslogReceiver);

                
                var task = Task.Run(() => syslogReceiver.ReceiveSyslogData(), cancellationToken);
                _syslogTasks.Add(task);

                Console.WriteLine($"[INFO] Syslog Receiver '{config.Name}' started listening on port {config.Port}.");
            }

            
            await Task.WhenAll(_syslogTasks);

            Console.WriteLine("[INFO] Syslog Scheduler has stopped all receivers.");
        }

        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel(); // Signal cancellation for all receivers
                Console.WriteLine("[INFO] Stopping all Syslog Receivers...");

                // Stop each receiver and log confirmation
                foreach (var receiver in _syslogReceivers)
                {
                    receiver.StopReceiver();
                }

                Task.WaitAll(_syslogTasks.ToArray()); // Ensure all tasks have stopped
                Console.WriteLine("[INFO] All Syslog Receivers have been stopped.");
            }
        }
    }
}
