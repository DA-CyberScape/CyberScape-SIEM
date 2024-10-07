namespace CS_DatabaseManager;

public class DbHostProvider
{
    //Custom list of DB Cluster Hosts.
    private readonly Dictionary<string, string[]> _hosts = new();
    
    private readonly string[] _remoteServerHosts = ["192.168.0.110", "192.168.0.111", "192.168.0.112"];
    private readonly string[] _dockerContainerHosts = ["172.17.0.2", "172.17.0.3", "172.17.0.4"];
    private readonly string[] _dockerContainerHosts2 = ["172.18.0.2", "172.18.0.3", "172.18.0.4"];

    
    public DbHostProvider()
    {
        _hosts.Add("RemoteServer", _remoteServerHosts);
        _hosts.Add("DockerContainer", _dockerContainerHosts);
        _hosts.Add("DockerContainer2", _dockerContainerHosts2);

    }

    //choose the hosts you want to connect to
    public string[] ProvideHosts()      
    {
        return _hosts["RemoteServer"];
    }
}