using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP;

public class NetflowScheduler
{
    private readonly TimeSpan _pollInterval;
    private readonly List<NfConfig> _nfConfigs;
    private readonly IDatabaseManager _databaseManager;
    private CancellationTokenSource _cancellationTokenSource;
    
    public NetflowScheduler(List<NfConfig> nfConfigs, IDatabaseManager databaseManager, int delayInSeconds = 10)
    {
        _nfConfigs = nfConfigs;
        _pollInterval = TimeSpan.FromSeconds(delayInSeconds);
        _databaseManager = databaseManager;
        _cancellationTokenSource = new CancellationTokenSource();
    }


    public async Task StartPollingAsync()
    {
        var cancellationToken = _cancellationTokenSource.Token;

        while (!cancellationToken.IsCancellationRequested)
        {
        }
        Console.WriteLine("Netflow Receiver stopped");
    }
    
    public void StopPolling()
    {
        if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
        {
            _cancellationTokenSource.Cancel();
            Console.WriteLine("Netflow Receiver is Stopping");
        }
    }
}