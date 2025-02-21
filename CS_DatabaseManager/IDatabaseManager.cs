namespace CS_DatabaseManager;

public interface IDatabaseManager
{
    Task<List<Dictionary<string, object>>> SelectData(string table, string condition, string order);
    Task CreateTable(string tableName, Dictionary<string /*Column names*/, Type /*Column types*/> columns, string primaryKey, 
        string? clusteringOrder);
    Task DeleteTable(string tableName);
    void SetKeySpace(string keySpaceName);
    Task InsertData(string table, Dictionary<string, Type> columns, Dictionary<string, object> data);
    [Obsolete("May not be needed")]
    void DeleteData(string table, string column, string value);
    [Obsolete("May not be needed")]
    void UpdateData(string table, string column, string value);
    void PrintKeyspaces();
    Task InsertBatchedData(string testTable, Dictionary<string,Type> columns, IEnumerable<Dictionary<string,object>> dataBatch);
}