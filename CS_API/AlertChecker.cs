using System;
using System.Net;
using System.Net.Mail;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;

namespace CS_API
{
    /// <summary>
    /// Class responsible for checking alerts at regular intervals and sending an email with the specified content if conditions are met.
    /// </summary>
    public class AlertChecker(List<Dictionary<string, object>> listOfAlerts)
    {
        public List<Dictionary<string, object>> ListOfAlerts = listOfAlerts;
        private CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private readonly int _delay = 180;
        public string AlertsPath = "";
        /// <summary>
        /// Starts the alert checker loop, which periodically sends API requests based on conditions and sends email alerts if conditions are met.
        /// </summary>

        public async void StartAlertChecker()
        {
            Console.WriteLine("STARTED ALERTCHECKER");
            var cancellationToken = _cancellationTokenSource.Token;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (ListOfAlerts.Count > 0)
                    {
                        foreach (var element in ListOfAlerts)
                        {
                            foreach (var entry in element)
                            {
                                Console.WriteLine(entry.Key + ": " + entry.Value);
                            }

                            string currentStartTime = "";
                            if (element["timestamp"].Equals(""))
                            {
                                Console.WriteLine("ADDING TIMESTAMP");
                                DateTime currentStartTimeStamp = DateTime.Now;
                                currentStartTime =
                                    $"&sd={currentStartTimeStamp.Year}-{currentStartTimeStamp.Month}-{currentStartTimeStamp.Day}&st={currentStartTimeStamp.Hour}:{currentStartTimeStamp.Minute}:{currentStartTimeStamp.Second}&et=23:59:59";
                                element["timestamp"] = currentStartTimeStamp;
                            }
                            else
                            {
                                currentStartTime = element["timestamp"].ToString();
                            }

                            DateTime newStartTimeStamp = DateTime.Now;
                            string nextStartTime =
                                $"&sd={newStartTimeStamp.Year}-{newStartTimeStamp.Month}-{newStartTimeStamp.Day}&st={newStartTimeStamp.Hour}:{newStartTimeStamp.Minute}:{newStartTimeStamp.Second}&et=23:59:59";
                            ;
                            string ans = await SendApiRequest("http://10.0.1.200:8000/database/",
                                "" + element["tabelle"].ToString(), "?" + element["condition"].ToString(),
                                currentStartTime);

                            if (!(ans.Equals("[]") || ans.Equals("")))
                            {
                                SendEmail(element["email_adresse"] + "", "ALERT " + element["name"],
                                    element["custom_message"].ToString());
                            }

                            Console.WriteLine("UPDATING TIMESTAMP");
                            element["timestamp"] = nextStartTime;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex}");
                }

                try
                {
                    Console.WriteLine("PUTTING STUFF INTO A FILE");

                    string newAlertsJson = JsonConvert.SerializeObject(ListOfAlerts, Formatting.Indented);
                    Console.WriteLine(newAlertsJson);
                    Console.WriteLine(AlertsPath);
                    await File.WriteAllTextAsync(AlertsPath, newAlertsJson, cancellationToken);
                    Console.WriteLine("PUTTING STUFF INTO A FILE");

                    Console.WriteLine($"WAITING FOR {_delay} seconds");
                    await Task.Delay(_delay * 1000, cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine($"ALERTCHECKER STOPPED GRACEFULLY");
                    return;
                }
            }

            Console.WriteLine("STOPPED ALERTCHECKER FOR SOME REASON");
        }
        /// <summary>
        /// Stops the alert checker.
        /// By cancelling the Cancellation token
        /// </summary>

        public void StopAlertChecker()
        {
            Console.WriteLine("STOPPING ALERTCHECKER");
            if (!_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                Console.WriteLine("AlertChecker is stopping");
            }

            Console.WriteLine("STOPPED ALERTCHECKER");
        }

        /// <summary>
        /// Restarts the alert checker by stopping the current instance and starting a new one.
        /// Uses <see cref="StopAlertChecker"/> to stop the current instance
        /// Uses <see cref="StartAlertChecker"/> to start a new instance
        /// </summary>
        public void RestartAlertChecker()
        {
            Console.WriteLine("RESTARTING ALERTCHECKER");
            StopAlertChecker();
            _cancellationTokenSource = new CancellationTokenSource();
            StartAlertChecker();
            Console.WriteLine("RESTARTED ALERTCHECKER");
        }




        /// <summary>
        /// Sends an API request with the specified parameters.
        /// </summary>
        /// <param name="url">The base URL for the API request.</param>
        /// <param name="table">The database table to query.</param>
        /// <param name="condition">The condition to be applied to the query.</param>
        /// <param name="starttime">The start time for the query.</param>
        /// <returns>A string containing the response from the API request</returns>
        private async Task<string> SendApiRequest(string url, string table, string condition, string starttime)
        {
            // example startime format sd=2025-01-19&st=13:00:00
            // http://10.0.1.200:8000/database/syslog?sd=2025-01-19&st=13:00:00&et=23:59:59&ip=10.0.1.254&severity=6 
            // example api request

            Console.WriteLine(
                $"SENDING API REQUEST WITH THE FOLLOWING PARAMETERS:{url} {table} {condition} {starttime} ");
            string answer = "";
            string apiEndpoint = url + table + condition + starttime;
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    Console.WriteLine(apiEndpoint);
                    HttpResponseMessage response = await client.GetAsync(apiEndpoint);
                    response.EnsureSuccessStatusCode();

                    answer = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(answer);
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine($"Request error: {e.Message}");
                }
            }


            return answer;
        }
        /// <summary>
        /// Sends an email with the specified recipient, subject, and content.
        /// This is to notify the Admin about the condition that has been met
        /// </summary>
        /// <param name="email">The recipient email address.</param>
        /// <param name="subject">The subject of the email.</param>
        /// <param name="content">The content of the email.</param>

        private void SendEmail(string email, string subject, string content)
        {
            try
            {
                string senderEmail = "cyberscapeuser@gmail.com";
                string appPassword = "xihu zvgm gafu mvbu";

                SmtpClient smtp = new SmtpClient("smtp.gmail.com", 587)
                {
                    Credentials = new NetworkCredential(senderEmail, appPassword),
                    EnableSsl = true
                };

                MailMessage mail = new MailMessage
                {
                    From = new MailAddress(senderEmail),
                    Subject = subject,
                    Body = content,
                    IsBodyHtml = false
                };

                mail.To.Add(email);
                smtp.Send(mail);
                Console.WriteLine("----------------------------");
                Console.WriteLine("Email sent successfully!");
                Console.WriteLine("----------------------------");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}