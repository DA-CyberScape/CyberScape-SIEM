using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;
using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using CS_DatabaseManager;
using System.Text.Json.Serialization;

namespace CS_SIEM_PROTOTYP
{
    public static class GuiApi
    {
        private static IDatabaseManager _databaseManager { set; get; }


        public static void ConfigureApi(this WebApplication app, IDatabaseManager db)
            // this bedeutet dass diese methode mit einem Webapplication object genutzt werden soll
        {
            _databaseManager = db;

            app.MapGet("/query", async (HttpContext context) =>
            {
                var query = context.Request.Query["q"].ToString();
                Console.WriteLine("------------");
                Console.WriteLine(query);
                Console.WriteLine("------------");

                if (string.IsNullOrEmpty(query))
                {
                    return Results.BadRequest("Query parameter 'q' is required.");
                }

                if (!IsSelectQuery(query))
                {
                    return Results.BadRequest("Only SELECT queries are allowed.");
                }

                try
                {
                    var results = await ExecuteQueryAsync(query);
                    var resultExampleTemp = new List<Dictionary<string, object>> {
                        new Dictionary<string, object> { { "ID", 1 }, { "Name", "Alice" }, { "Age", 30 }, { "IsEmployee", true }, { "Salary", 50000.0 } },
                        new Dictionary<string, object> { { "ID", 2 }, { "Name", "Bob" }, { "Age", 25 }, { "IsEmployee", false }, { "Salary", null } },
                        new Dictionary<string, object> { { "ID", 3 }, { "Name", "Charlie" }, { "Age", 35 }, { "IsEmployee", true }, { "Salary", 75000.0 } }
                    };

                    var response = new QueryResponse
                    {
                        Rows = results 
                    };

                    Console.WriteLine("Before sending");

                    return Results.Json(response, MyJsonContext.Default.QueryResponse);

                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error executing query: {ex.Message}");
                    return Results.StatusCode(StatusCodes.Status500InternalServerError);
                }
            });
        }

        private static bool IsSelectQuery(string query)
        {
            // Basic check to see if the query starts with SELECT (case-insensitive)
            var trimmedQuery = query.Trim().ToUpperInvariant();
            return trimmedQuery.StartsWith("SELECT") && !trimmedQuery.Contains(';');
        }

        public static (string tableName, string whereCondition, string orderByElement) ExtractWhereAndOrderBy(
            string sqlQuery)
        {
            Console.WriteLine(sqlQuery);
            string whereCondition = string.Empty;
            string orderByElement = string.Empty;
            string tableName = string.Empty;

            Regex tableRegex = new Regex(@"FROM\s+(?<TABLE>[^\s]+)", RegexOptions.IgnoreCase);
            Regex whereRegex = new Regex(@"WHERE\s+(?<WHERE>.*?)\s+(ORDER\s+BY|$)", RegexOptions.IgnoreCase);
            Regex orderRegex = new Regex(@"ORDER\s+BY\s+(?<ORDER>.*)(\s+|$)", RegexOptions.IgnoreCase);
            
            string pattern = @"\bWHERE\b\s+(.*?)(?:\s+\bORDER BY\b\s+(.*))?$";
                    
                    // Perform the match
            Match match = Regex.Match(sqlQuery, pattern, RegexOptions.IgnoreCase);
            
            if (match.Success)
            {
                // Extract WHERE clause, if present
                string whereClause = match.Groups[1].Success ? match.Groups[1].Value : "";
                Console.WriteLine("WHERE Clause: " + whereClause);
                whereCondition = whereClause;
                // Extract ORDER BY clause, if present (optional)
                string orderByClause = match.Groups[2].Success ? match.Groups[2].Value : "";
                Console.WriteLine("ORDER BY Clause: " + orderByClause);
                orderByElement = orderByClause;
            }
            else
            {
                Console.WriteLine("No WHERE clause or ORDER BY clause found.");
            }
            

            Match tableMatch = tableRegex.Match(sqlQuery);
            if (tableMatch.Success)
            {
                tableName = tableMatch.Groups["TABLE"].Value.Trim();
            }

            return (tableName, whereCondition, orderByElement);
        }

        public static async Task<List<Dictionary<string, string>>> ExecuteQueryAsync(string query)
        {
            var whereAndOrderBy = ExtractWhereAndOrderBy(query);
            Console.WriteLine(whereAndOrderBy);

            Console.WriteLine(
                $"{whereAndOrderBy.tableName}, {whereAndOrderBy.whereCondition}, {whereAndOrderBy.orderByElement}");


            List<Dictionary<string, object>> resultDict = await _databaseManager.SelectData(
                $"{whereAndOrderBy.tableName}",
                $"{whereAndOrderBy.whereCondition}", $"{whereAndOrderBy.orderByElement}");
            List<Dictionary<String, String>> queryResult = ConvertObjectToString(resultDict);
            
            for (int i = 0; i < queryResult.Count; i++)
            {
                // Console.WriteLine($"\nDictionary {i + 1}:");
    
                //foreach (var entry in queryResult[i])
                //{
                //    string key = entry.Key;
                //    string value = entry.Value;
    
                    // Display key, value, and type of value
                //   Console.WriteLine($"  Key: '{key}'");
                //    Console.WriteLine($"    Value: '{value}'");
                //    Console.WriteLine($"    Type: '{value?.GetType() ?? typeof(object)}'");
                // }
            }
            
            
            
            

            return queryResult;
        }
        
        

        public static List<Dictionary<String, String>> ConvertObjectToString(List<Dictionary<String, Object>> inputList)
        {
            List<Dictionary<String, String>> result = new List<Dictionary<String, String>>();

            foreach (var dict in inputList)
            {
                Dictionary<String, String> newDict = new Dictionary<String, String>();
                foreach (var kvp in dict)
                {
                    // Convert the Object value to String using ToString() method
                    newDict[kvp.Key] = kvp.Value?.ToString() ?? "null";
                }

                result.Add(newDict);
            }

            return result;
        }
    }
    
        


}