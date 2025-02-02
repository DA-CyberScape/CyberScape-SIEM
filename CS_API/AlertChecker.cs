using System;
using System.Net;
using System.Net.Mail;
namespace CS_API;


public class AlertChecker(List<Dictionary<string, object>> listOfAlerts)
{
    private List<Dictionary<string, object>> _listOfAlerts = listOfAlerts;
    private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
    private readonly int _delay = 180;

    public async void StartAlertChecker()
    {
        Console.WriteLine("STARTED ALERTCHECKER");
        var cancellationToken = _cancellationTokenSource.Token;
        
        while (!cancellationToken.IsCancellationRequested)
        {
            foreach (var element in _listOfAlerts)
            {
                foreach (var entry in element)
                {
                    Console.WriteLine(entry.Key + ": " + entry.Value);
                }

                string ans = SendApiRequest("localhost", element["tabelle"].ToString(), element["condition"].ToString(), "current time");
                // send email
                // do some stuff with api
                // check if string has a match
                // send email if required


            }
            try
            {
                
                Console.WriteLine($"WAITING FOR {_delay} seconds");
                await Task.Delay(_delay * 1000, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine($"ALERTCHECKER STOPPED GRACEFULLY");
                return;
            }
        }
        Console.WriteLine("STOPPED ALERTCHECKER");
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
        StartAlertChecker();
        Console.WriteLine("RESTARTED ALERTCHECKER");
    }

    public void UpdateListOfDictionary(List<Dictionary<string, object>> newListOfAlerts)
    {
        _listOfAlerts = newListOfAlerts;
        // RestartAlertChecker()
    }

    

    private string SendApiRequest(string url, string table, string condition, string starttime)
    {
        // example startime format sd=2025-01-19&st=13:00:00
        Console.WriteLine($"SENDING API REQUEST WITH THE FOLLOWING PARAMETERS:{url} {table} {condition} {starttime} ");
        string answer = "";

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