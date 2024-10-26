using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP;

public class NetflowScheduler
{
    private readonly int _delay;
    private readonly List<NfConfig> _nfConfigs;
    private readonly IDatabaseManager _databaseManager;
    private CancellationTokenSource _cancellationTokenSource;
    
    public NetflowScheduler(List<NfConfig> nfConfigs, IDatabaseManager databaseManager, int delayInSeconds = 10)
    {
        _nfConfigs = nfConfigs;
        _delay = delayInSeconds;
        _databaseManager = databaseManager;
        _cancellationTokenSource = new CancellationTokenSource();
    }


    public async Task StartPollingAsync()
    {
        var cancellationToken = _cancellationTokenSource.Token;
        Console.WriteLine("[INFO] Starting Netflow Scheduler...");

        while (!cancellationToken.IsCancellationRequested)
        {
            Console.WriteLine("[INFO] Polling cycle started.");
            
            
            
            
            foreach (var config in _nfConfigs)
            {
                Console.WriteLine($"[INFO] Polling Netflow data for configuration ID: {config.Id}, Name: {config.Name}, Port: {config.Port}");

                try
                {
                   
                    Console.WriteLine($"[INFO] Successfully polled data for configuration ID: {config.Id}");
                        
                 
                    
                }
                catch (Exception ex) when (!(ex is TaskCanceledException))
                {
                    Console.WriteLine($"[ERROR] Error while polling data for configuration ID: {config.Id}: {ex.Message}");
                }
            }
            
            
            Console.WriteLine("[INFO] Inserting Netflow data into the database...");
            //TODO INSERT DATA INTO DATABASE
            Console.WriteLine($"[INFO] Data from configurations has been inserted into the database.");
            
            Console.WriteLine("[INFO] Polling cycle completed. Waiting for the next interval...");
            try
            {
                await Task.Delay(_delay * 1000, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("[INFO] Polling has been canceled.");
                break;
            }

            
            
            
            
            
            
            
            
            
            
            
            
            
            
        }
        Console.WriteLine("[INFO] Netflow Scheduler stopped.");
    }
    
    public void StopPolling()
    {
        if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            Console.WriteLine("[INFO] Netflow Scheduler is stopping...");
        }
    }
}