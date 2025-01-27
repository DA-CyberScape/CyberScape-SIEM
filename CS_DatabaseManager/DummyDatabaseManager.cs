using System.Net;
using System.Text;

namespace CS_DatabaseManager;

public class DummyDatabaseManager : IDatabaseManager
{
    private string _keySpace = "TestKeyspace";

    public Task<List<Dictionary<string, object>>> SelectData(string table, string condition, string order)
    {
        throw new NotImplementedException();
    }

    public Task CreateTable(string tableName, Dictionary<string, Type> columns, string primaryKey = "UUID", string? clusteringOrder = null)
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
            CREATE TABLE IF NOT EXISTS ""{_keySpace}"".""{tableName}"" (
                {columnDefinitions}
                PRIMARY KEY ({primaryKey})
            )";

        Console.WriteLine("Creating Table: \n" + createTableCql);
        return Task.CompletedTask;
    }

    public void DeleteTable(string tableName)
    {
        // TODO: Delete Tables which are not defined in the "config" file? Maybe call this in CreateTable()
        var dropTableCql = $@"DROP TABLE IF EXISTS ""{_keySpace}"".""{tableName}""";

        Console.WriteLine("Dropping Table: \n" + dropTableCql);
    }


    public void SetKeySpace(string keySpaceName)
    {
        _keySpace = keySpaceName;
    }

    public Task InsertData(string table, Dictionary<string, Type> columns, Dictionary<string, object> data)
    {
        if (!columns.Keys.All(data.ContainsKey))
        {
            throw new ArgumentException("Data dictionary contains keys not present in columns dictionary.");
        }

        var columnNames = string.Join(", ", columns.Keys);
        var values = string.Join(", ", columns.Keys.Select(column => FormatValue(data[column])));

        var insertCql = $@"
        INSERT INTO ""{_keySpace}"".""{table}"" ({columnNames})
        VALUES ({values})
    ";

        Console.WriteLine("Inserting Data: \n" + insertCql);

        return Task.CompletedTask;
    }

    private string FormatValue(object value)
    {
        return (value switch
        {
            string s => $"'{s.Replace("'", "''")}'",
            DateTime dt => $"'{dt:yyyy-MM-dd HH:mm:ss}'",
            Guid g => $"'{g}'",
            _ => value.ToString()
        })!;
    }

    public void DeleteData(string table, string column, string value)
    {
        throw new NotImplementedException();
    }

    public void UpdateData(string table, string column, string value)
    {
        throw new NotImplementedException();
    }

    public void PrintKeyspaces()
    {
        Console.WriteLine(_keySpace);
    }

    public Task InsertBatchedData(string table, Dictionary<string, Type> columns,
        IEnumerable<Dictionary<string, object>> dataBatch)
    {
        if (dataBatch == null || !dataBatch.Any())
        {
            throw new ArgumentException("Data batch cannot be null or empty.");
        }

        var batch = new List<string>();

        foreach (var data in dataBatch)
        {
            if (!columns.Keys.All(data.ContainsKey))
            {
                throw new ArgumentException("Data dictionary contains keys not present in columns dictionary.");
            }

            var columnNames = string.Join(", ", columns.Keys);
            var values = string.Join(", ", columns.Keys.Select(column => FormatValue(data[column])));

            var insertCql = $@"
            INSERT INTO ""{_keySpace}"".""{table}"" ({columnNames})
            VALUES ({values})
            ";
            batch.Add(insertCql);
        }
    
        Console.WriteLine("Inserting Batched Data: \n" + string.Join("\n", batch));
        return Task.CompletedTask;
    }
}