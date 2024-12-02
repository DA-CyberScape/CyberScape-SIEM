using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using CS_DatabaseManager;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json.Serialization;
using System.Text.Json;


namespace CS_SIEM_PROTOTYP
{
    public class ApiStarter
    {
        private static WebApplication? _app;
        private static CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private IDatabaseManager _db;

        public ApiStarter(IDatabaseManager db)
        {
            _db = db;
        }

        public async Task StartApiAsync()
        {
            Console.WriteLine("[INFO] Initializing API...");

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(5000); // HTTP
                /*options.ListenAnyIP(5001, listenOptions =>
                {
                    listenOptions.UseHttps(); // HTTPS
                });*/
            });

            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder.AllowAnyOrigin() // Allows requests from any origin
                        // TODO SAI WENN DIE WEBSITE AUF DEM SERVER IN DER UCS LAUEFT NUR DIESE IP ERLAUBEN
                        .AllowAnyMethod() // Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
                        .AllowAnyHeader(); // Allows all headers
                });
            });
            builder.Services.AddControllers();
            // _app.UseCors("AllowAll");
            _app = builder.Build();
            _app.UseCors("AllowAll"); 
            _app.MapControllers();

            Console.WriteLine("[INFO] Starting API configuration...");
            _app.ConfigureApi(_db);

            Console.WriteLine("[INFO] Running API...");
            try
            {
                await _app.RunAsync(_cancellationTokenSource.Token);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("[INFO] API shutdown has been requested.");
            }
        }

        public void StopApi()
        {
            if (_app != null && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                Console.WriteLine("[INFO] Stopping API...");
                _app.StopAsync();
                _cancellationTokenSource.Cancel();
                Console.WriteLine("[INFO] API stopped gracefully.");
            }
            else
            {
                Console.WriteLine("[WARN] API stop requested, but API was not running or has already been stopped.");
            }
        }
    }
}