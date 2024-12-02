using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace CS_DatabaseManager;

public class DbHostProvider
{
    //Custom list of DB Cluster Hosts.
    private List<ClusterList> _clusterLists = new();

    private const string
        ConfigFilePath =
            "/home/cyberscape_admin/CyberScape-SIEM/App_Configurations/Database_IPs.yaml"; // Path to your YAML file

    public DbHostProvider()
    {
        LoadHosts();
    }

    private void LoadHosts()
    {
        if (File.Exists(ConfigFilePath))
        {
            var yamlContent = File.ReadAllText(ConfigFilePath);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();
    
            // Deserialize YAML content into ClusterListsConfiguration
            var config = deserializer.Deserialize<ClusterListsConfiguration>(yamlContent);
            
            if (config != null && config.clusterlists != null)
            {
                _clusterLists = config.clusterlists;  // Assign to the internal list
            }
            else
            {
                throw new Exception("Deserialization failed, config is null or clusterlists is empty.");
            }
        }
        else
        {
            throw new FileNotFoundException($"Config file not found: {ConfigFilePath}");
        }
    }


    public string[] ProvideHosts()
    {
        // Find the active cluster list
        var activeCluster = _clusterLists.FirstOrDefault(c => c.Active);
        return activeCluster != null ? activeCluster.list.ToArray() : Array.Empty<string>();
    }

    public bool isProduction()
    {
        //if active cluster is Local Cluster then yes, else no
        var activeCluster = _clusterLists.FirstOrDefault(c => c.Active);
        return activeCluster is { Production: true };
    }
    
    public void SaveHosts()
    {
        
    }
}

public class ClusterList
{
    public string listname { get; set; }
    public List<string> list { get; set; }
    public bool Active { get; set; }
    public bool Production { get; set; }
}

public class ClusterListsConfiguration
{
    public List<ClusterList> clusterlists { get; set; } // Should match 'clusterlists' in YAML
}