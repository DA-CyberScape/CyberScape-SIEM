using System;
using System.Net;
using System.Net.Mail;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
namespace CS_API;


public class AlertChecker(List<Dictionary<string, object>> listOfAlerts)
{
    public List<Dictionary<string, object>> ListOfAlerts = listOfAlerts;
    private CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
    private readonly int _delay = 10;
    public string AlertsPath = "";

    public async void StartAlertChecker()
    {
        Console.WriteLine("STARTED ALERTCHECKER");
        var cancellationToken = _cancellationTokenSource.Token;
        
        while (!cancellationToken.IsCancellationRequested)
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
                        "" + element["tabelle"].ToString(), "?" + element["condition"].ToString(), currentStartTime);

                    if (!(ans.Equals("[]") || ans.Equals("")))
                    {
                        SendEmail(element["email_adresse"] + "", "ALERT " + element["name"], ans);
                    }

                    Console.WriteLine("UPDATING TIMESTAMP");
                    element["timestamp"] = nextStartTime;



                }
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

    public void RestartAlertChecker()
    {
        Console.WriteLine("RESTARTING ALERTCHECKER");
        StopAlertChecker();
        _cancellationTokenSource = new CancellationTokenSource();
        StartAlertChecker();
        Console.WriteLine("RESTARTED ALERTCHECKER");
    }

    public void UpdateListOfDictionary(List<Dictionary<string, object>> newListOfAlerts)
    {
        ListOfAlerts = newListOfAlerts;
        // RestartAlertChecker()
    }

    

    private async Task<string> SendApiRequest(string url, string table, string condition, string starttime)
    {
        // example startime format sd=2025-01-19&st=13:00:00
        // http://10.0.1.200:8000/database/syslog?sd=2025-01-19&st=13:00:00&et=23:59:59&ip=10.0.1.254&severity=6 
        // example api request
        
        Console.WriteLine($"SENDING API REQUEST WITH THE FOLLOWING PARAMETERS:{url} {table} {condition} {starttime} ");
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
            Console.WriteLine("Email sent successfully!");
        }
        catch(Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }


    }
    
}