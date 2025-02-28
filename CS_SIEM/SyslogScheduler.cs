﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CS_DatabaseManager;
using Microsoft.Extensions.Logging;

namespace CS_SIEM
{
    /// <summary>
    /// Schedules and manages Syslog receivers for listening to Syslog messages on specified ports.
    /// </summary>
    public class SyslogScheduler
    {
        private readonly int _delay;
        private readonly List<SyslogConfig> _syslogConfigs;
        private readonly IDatabaseManager _databaseManager;
        private readonly List<SyslogReceiver> _syslogReceivers;
        private readonly List<Task> _syslogTasks;
        private CancellationTokenSource _cancellationTokenSource;
        private ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="SyslogScheduler"/> class.
        /// </summary>
        /// <param name="syslogConfigs">A list of Syslog configurations.</param>
        /// <param name="databaseManager">The database manager for storing received Syslog messages.</param>
        /// <param name="logger">The logger for logging information and errors.</param>
        /// <param name="delayInSeconds">The delay in seconds between processing Syslog messages. Default is 10 seconds.</param>
        public SyslogScheduler(List<SyslogConfig> syslogConfigs, IDatabaseManager databaseManager, ILogger logger,
            int delayInSeconds = 10)
        {
            _syslogConfigs = syslogConfigs;
            _delay = delayInSeconds;
            _databaseManager = databaseManager;
            _syslogReceivers = new List<SyslogReceiver>();
            _syslogTasks = new List<Task>();
            _cancellationTokenSource = new CancellationTokenSource();
            _logger = logger;
        }


        /// <summary>
        /// Starts analyzing Syslog messages by initializing and starting Syslog receivers for each configuration.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public async Task StartAnalyzingAsync()
        {
            var cancellationToken = _cancellationTokenSource.Token;

            _logger.LogInformation("[INFO] Starting Syslog Scheduler...");


            foreach (var config in _syslogConfigs)
            {
                var syslogReceiver = new SyslogReceiver(_databaseManager, config.Port, _logger,_delay);
                _syslogReceivers.Add(syslogReceiver);


                var task = Task.Run(() => syslogReceiver.ReceiveSyslogData(), cancellationToken);
                _syslogTasks.Add(task);

                _logger.LogInformation($"[INFO] Syslog Receiver '{config.Name}' started listening on port {config.Port}.");
            }


            await Task.WhenAll(_syslogTasks);

            _logger.LogInformation("[INFO] Syslog Scheduler has stopped all receivers.");
        }

        /// <summary>
        /// Stops all Syslog receivers and cancels the listening tasks.
        /// </summary>
        public void StopPolling()
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel(); 
                _logger.LogInformation("[INFO] Stopping all Syslog Receivers...");

                
                foreach (var receiver in _syslogReceivers)
                {
                    receiver.StopReceiver();
                }

                Task.WaitAll(_syslogTasks.ToArray()); 
                _logger.LogInformation("[INFO] All Syslog Receivers have been stopped.");
            }
        }
    }
}