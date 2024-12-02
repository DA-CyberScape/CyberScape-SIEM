using System.Net;
using System.Text;
using Cassandra;
using Cassandra.Data.Linq;

namespace CS_DatabaseManager;

public class ScyllaDatabaseManager : IDatabaseManager
{
    private readonly Cluster _cluster;
    private readonly ISession _session;
    private Dictionary<String, object> _tableCache = new();

    public ScyllaDatabaseManager(DbHostProvider dbHostProvider)
    {
        //TODO: cache a Map with table names and their column definitions from a file?

        _cluster =
            Cluster.Builder()
                .AddContactPoints(dbHostProvider.ProvideHosts()).WithExecutionProfiles(options =>
                    options.WithProfile("profile1", builder => builder.WithConsistencyLevel(ConsistencyLevel.Quorum)))
                .Build();

        _session =
            _cluster.Connect();
        Console.WriteLine("[INFO] Successfully Connected with the Database.");


        SetKeySpace(dbHostProvider.isProduction() ? "Production" : "Testing");

        var infoRunningDatabaseInProductionMode = dbHostProvider.isProduction()
            ? "[INFO] Running Database in Production mode."
            : "[INFO] Running Database in Testing mode.";
        Console.WriteLine(infoRunningDatabaseInProductionMode);


        // Collects Metadata and caches it locally
        // Console.WriteLine("Collecting Metadata on Startup");
        //     var tables = _cluster.Metadata.GetTables(_session.Keyspace);
        //     foreach (var tableName in tables)
        //     {
        //         Console.WriteLine("______________");
        //         Console.WriteLine(tableName);
        //         UpdateCache(_session.Keyspace, tableName);
        //     }
    }


    public async Task CreateTable(string tableName, Dictionary<string, Type> columns, string primaryKey = "UUID")
    {
        var typeMapping = new Dictionary<Type, string>
        {
            { typeof(int), "INT" },
            { typeof(long), "BIGINT" },
            { typeof(float), "FLOAT" },
            { typeof(double), "DOUBLE" },
            { typeof(bool), "BOOLEAN" },
            { typeof(string), "TEXT" },
            { typeof(DateTime), "TIMESTAMP" },
            { typeof(Guid), "UUID" },
            { typeof(byte[]), "BLOB" },
            { typeof(IPAddress), "INET" }
        };


        var columnDefinitions = new StringBuilder();
        foreach (var column in columns)
        {
            if (typeMapping.TryGetValue(column.Value, out var cqlType))
            {
                columnDefinitions.Append($"{column.Key} {cqlType}, ");
            }
            else
            {
                throw new ArgumentException($"Type '{column.Value}' is not supported.");
            }
        }

//        columnDefinitions.Append($"{primaryKey} UUID");

        var createTableCql = $@"
            CREATE TABLE IF NOT EXISTS ""{_session.Keyspace}"".""{tableName}"" (
                {columnDefinitions}
                PRIMARY KEY ({primaryKey})
            )";

        Console.WriteLine("Creating Table: \n" + createTableCql);

        var statement = new SimpleStatement(createTableCql);
        await _session.ExecuteAsync(statement).ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                Console.WriteLine($"Error creating table: {t.Exception?.GetBaseException().Message}");
            }
            else
            {
                Console.WriteLine($"Table '{tableName}' created successfully.");
                //TODO: cache the table name and column definitions in to a Map
                ////UpdateCache(_session.Keyspace, tableName);
            }
        });
        // await Task.Delay(5000);
    }

    /*
     * <summary>
     * Updates the Cache with the latest table definitions
     * </summary>
     */
    private void UpdateCache(string keySpace, string tableName)
    {
//        var tableMetadata = _cluster.Metadata.GetTable(keySpace, tableName); // this line causes the error
//        if (tableMetadata != null)
//        {
//            var table = tableMetadata.Name;
//        }
//        else
//        {
//            Console.WriteLine($"Table '{tableName}' in keyspace '{keySpace}' not found.");
//        }
//        var columns = table.TableColumns;
//        var columnDefinitions = columns.ToDictionary(column => column.Name, column => column.TypeCode);
//
//        _tableCache[keySpace + "." + tableName] = columnDefinitions;
    }

    public void DeleteTable(string tableName)
    {
        // TODO: Delete Tables which are not defined in the "config" file? Maybe call this in CreateTable()
        var dropTableCql = $@"DROP TABLE IF EXISTS ""{_session.Keyspace}"".""{tableName}""";

        Console.WriteLine("Dropping Table: \n" + dropTableCql);

        var statement = new SimpleStatement(dropTableCql);
        _session.ExecuteAsync(statement).ContinueWith(t =>
        {
            Console.WriteLine(t.IsFaulted
                ? $"Error dropping table: {t.Exception?.GetBaseException().Message}"
                : $"Table '{tableName}' dropped successfully.");
        });
    }

    public void SetKeySpace(string keySpaceName)
    {
        var currentKeyspace = _session.Keyspace;
        var availableKeyspace = _cluster.Metadata.GetKeyspaces();

        if (availableKeyspace.Contains(keySpaceName) && currentKeyspace != keySpaceName)
        {
            _session.ChangeKeyspace(keySpaceName);

            Console.WriteLine("Set Keyspace to " + keySpaceName);
        }
        else
        {
            Console.WriteLine("Keyspace does not exist. Creating Keyspace...");
            var datacentersReplicationFactors = new Dictionary<string, int>
            {
                { "cyberscape_datacenter", 3 }
            };
            var replicationProperty =
                ReplicationStrategies.CreateNetworkTopologyStrategyReplicationProperty(datacentersReplicationFactors);
            _session.CreateKeyspaceIfNotExists(keySpaceName, replicationProperty);
            _session.ChangeKeyspace(keySpaceName);
        }
    }

    public async Task InsertData(string table, Dictionary<string, Type> columns, Dictionary<string, object> data)
    {
        if (!columns.Keys.All(data.ContainsKey))

        {
            Console.WriteLine("Data Dictionary: _____________________-");
            foreach (var d in data)
            {
                Console.WriteLine(d.Key + ": " + d.Value);
            }

            Console.WriteLine("Column Dictionary: _____________________-");
            foreach (var c in columns)
            {
                Console.WriteLine(c.Key + ": " + c.Value);
            }

            throw new ArgumentException("Data dictionary contains keys not present in columns dictionary.");
        }
        //TODO: get the column definitions from the cache and internally add the primary key to the data (which is a UUID)
        //the reason for this is so that we don't have to pass the primary key as a column and can generate the UUID internally

        var columnNames = string.Join(", ", columns.Keys);
        var valuePlaceholders = string.Join(", ", Enumerable.Range(0, columns.Count).Select(_ => "?"));

        var insertCql = $@"
            INSERT INTO ""{_session.Keyspace}"".""{table}"" ({columnNames})
            VALUES ({valuePlaceholders})
        ";
        var values = columns.Keys.Select(column => data[column]).ToArray();

        // Console.WriteLine(insertCql);
        // Console.WriteLine(values);
        var statement = new SimpleStatement(insertCql, values);
        // Console.WriteLine(statement.ToString());

        // foreach (var val in values)
        // {
        // Console.Write(val + " " + val.GetType() + " ");
        // Console.WriteLine();
        // }

        await _session.ExecuteAsync(statement).ContinueWith(t =>
        {
            if (t.IsFaulted) Console.WriteLine($"Error inserting data: {t.Exception?.GetBaseException().Message}");
        });
        // await Task.Delay(1000);
    }

    public async Task InsertBatchedData(string table, Dictionary<string, Type> columns,
        IEnumerable<Dictionary<string, object>> dataBatch)
    {
        if (dataBatch == null || !dataBatch.Any())
        {
            throw new ArgumentException("Data batch cannot be null or empty.");
        }

        var batch = new BatchStatement();

        foreach (var data in dataBatch)
        {
            if (!columns.Keys.All(data.ContainsKey))
            {
                throw new ArgumentException("Data dictionary contains keys not present in columns dictionary.");
            }

            var columnNames = string.Join(", ", columns.Keys);
            var valuePlaceholders = string.Join(", ", Enumerable.Range(0, columns.Count).Select(i => "?"));

            var insertCql = $@"
            INSERT INTO ""{_session.Keyspace}"".""{table}"" ({columnNames})
            VALUES ({valuePlaceholders})
            ";

            var values = columns.Keys.Select(column => data[column]).ToArray();

            var statement = new SimpleStatement(insertCql, values);
            batch.Add(statement);
        }

        await _session.ExecuteAsync(batch).ContinueWith(t =>
        {
            Console.WriteLine(t.IsFaulted
                ? $"Error executing batch: {t.Exception?.GetBaseException().Message}"
                : "Batch executed successfully.");
        });
    }

    public async Task<List<Dictionary<string, object>>> SelectData(string table, string condition = "",
        string order = "")
    {
        //check if table exists in keyspace
        var containsInTable = _cluster.Metadata.GetTables(_session.Keyspace).Contains(table);

        if (!containsInTable)
        {
            // var containsInView = _cluster.Metadata.GetMaterializedView(_session.Keyspace, table);
            // Console.WriteLine("VIEW: " + containsInView);
            // throw new ArgumentException($"Table '{table}' does not exist in keyspace '{_session.Keyspace}'.");
        }


        var selectCql = $@"SELECT * FROM ""{_session.Keyspace}"".""{table}""";

        if (!string.IsNullOrWhiteSpace(condition))
        {
            selectCql += condition;
        }

        if (!string.IsNullOrWhiteSpace(order))
        {
            selectCql += $" ORDER {order}";
        }
        //TODO: SAI SCHAU DIR DAS AN FUER DIE API
        //https://opensource.docs.scylladb.com/stable/

        selectCql += ";";
        Console.WriteLine("Executing Query: \n" + selectCql);

        var statement = new SimpleStatement(selectCql);

        try
        {
            var rowSet = await _session.ExecuteAsync(statement);
            var results = new List<Dictionary<string, object>>();

            // Iterate through each row in the result set
            foreach (var row in rowSet)
            {
                var rowData = new Dictionary<string, object>();
                // Use rowSet.Columns to get column names and values
                foreach (var column in rowSet.Columns)
                {
                    rowData[column.Name] = row[column.Name];
                }

                results.Add(rowData);
            }

            // foreach (var row in results)
            // {
            // Console.WriteLine(string.Join(", ", row.Select(kv => $"{kv.Key}: {kv.Value}")));
            // }
            // foreach (var v in results)
            // {
            //     foreach (var a in v)
            //     {
            //         Console.WriteLine("KEY: "+a.Key);
            //         Console.WriteLine("VALUE: "+a.Value.GetType());
            //     }
            // }
            Console.WriteLine("Query executed successfully.");

            return results;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error executing query: {e.Message}");
            return [];
        }
    }

    [Obsolete("May not be needed")]
    public void DeleteData(string table, string column, string value)
    {
        throw new NotImplementedException();
    }

    [Obsolete("May not be needed")]
    public void UpdateData(string table, string column, string value)
    {
        throw new NotImplementedException();
    }

    public void PrintKeyspaces()
    {
        var keyspaces = _cluster.Metadata.GetKeyspaces();
        Console.WriteLine("All Keyspaces:");
        foreach (var keyspace in keyspaces)
        {
            Console.WriteLine(keyspace);
        }

        Console.WriteLine("Current Keyspace: " + _session.Keyspace);
    }
}