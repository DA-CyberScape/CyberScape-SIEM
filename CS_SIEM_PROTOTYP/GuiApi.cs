using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;
using System;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cassandra;

using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP
{
    
    
    
    
    
    public static class GuiApi
    {

        private static IDatabaseManager _databaseManager {set;get;}


        public static void ConfigureApi(this WebApplication app, IDatabaseManager db)
            // this bedeutet dass diese methode mit einem Webapplication object genutzt werden soll
        {
            _databaseManager = db;

            app.MapGet("/query", async (HttpContext context) =>
            {
                var query = context.Request.Query["q"].ToString();
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
                   
                    

                    var response = new
                    {
                        query = new
                        {
                            query_string = query,
                            query_timestamp = DateTime.UtcNow,
                        },
                        rows = results
                    };
                    
                    return Results.Ok(response);
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

        public static (string tableName, string whereCondition, string orderByElement) ExtractWhereAndOrderBy(string sqlQuery)
        {
            string whereCondition = string.Empty;
            string orderByElement = string.Empty;
            string tableName = string.Empty;
            
            Regex tableRegex = new Regex(@"FROM\s+(?<TABLE>[^\s]+)", RegexOptions.IgnoreCase);
            Regex whereRegex = new Regex(@"WHERE\s+(?<WHERE>.*?)\s+(ORDER\s+BY|$)", RegexOptions.IgnoreCase);
            Regex orderRegex = new Regex(@"ORDER\s+BY\s+(?<ORDER>.*)(\s+|$)", RegexOptions.IgnoreCase);
            
            Match whereMatch = whereRegex.Match(sqlQuery);
            if (whereMatch.Success)
            {
                whereCondition = whereMatch.Groups["WHERE"].Value.Trim();
            }

            
            Match orderByMatch = orderRegex.Match(sqlQuery);
            if (orderByMatch.Success)
            {
                orderByElement = orderByMatch.Groups["ORDER"].Value.Trim();
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
            
            Console.WriteLine($"{whereAndOrderBy.tableName}, {whereAndOrderBy.whereCondition}, {whereAndOrderBy.orderByElement}");
            
            
            var resultDict = await _databaseManager.SelectData($"{whereAndOrderBy.tableName}", $"{whereAndOrderBy.whereCondition}", $"{whereAndOrderBy.orderByElement}");
            List<Dictionary<String, String>> queryResult = ConvertObjectToString(resultDict);
            
            
            
            
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
