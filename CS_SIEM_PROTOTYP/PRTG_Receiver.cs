using System.Text.Json;
using CS_DatabaseManager;

namespace CS_SIEM_PROTOTYP;

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Linq;

public class PrtgReceiver : IDataReceiver
{
    
    private readonly IDatabaseManager _databaseManager;
    public PrtgReceiver(IDatabaseManager databaseManager)
    {
        _databaseManager = databaseManager;
    }
    public void ReceiveData()
    {
        throw new NotImplementedException();
    }

    public async Task<List<Device>> FetchDeviceWithSensors(string prtgUrl, string apitoken)
    {
        List<Device> devices = await this.FetchDevices(prtgUrl, apitoken);
        foreach (var device in devices)
        {
            List<Sensor> sensors = await this.FetchSensors(prtgUrl, apitoken, device.Name);
            device.Sensors = sensors;
        }

        return devices;
    }


    public async Task<List<Device>> FetchDevices(string prtgUrl, string apitoken)
    {
        string url = $"{prtgUrl}/api/table.json?content=devices&output=json&columns=objid,device&apitoken={apitoken}";
        // output device name and objid of all devices on the prtg server
        var devices = new List<Device>();
        Console.WriteLine(url);

        using (HttpClient client = new HttpClient())
        {
            try
            {
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                string responseBody = await response.Content.ReadAsStringAsync();
                var jsonDoc = JsonDocument.Parse(responseBody);

                foreach (var item in jsonDoc.RootElement.GetProperty("devices").EnumerateArray())
                {
                    int deviceId = item.GetProperty("objid").GetInt32();
                    string deviceName = item.GetProperty("device").GetString();
                    devices.Add(new Device { Id = deviceId, Name = deviceName });
                }
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("Request error: " + e.Message);
            }
            catch (JsonException e)
            {
                Console.WriteLine("JSON parsing error: " + e.Message);
            }
        }

        return devices;
    }

    public async Task<List<Sensor>> FetchSensors(string prtgUrl, string apitoken, string deviceName)
    {
        string url =
            $"{prtgUrl}/api/table.json?content=sensors&output=json&columns=sensor,objid,lastvalue,status,message&filter_device={Uri.EscapeDataString(deviceName)}&apitoken={apitoken}";
        // outputs the object id and name of the sensor for device DEVICENAME
        var sensors = new List<Sensor>();
        Console.WriteLine(url);
        using HttpClient client = new HttpClient();
        HttpResponseMessage response = await client.GetAsync(url);

        if (response.IsSuccessStatusCode)
        {
            string responseBody = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(responseBody);

            // Console.WriteLine("Sensors retrieved from PRTG:");
            foreach (var item in jsonDoc.RootElement.GetProperty("sensors").EnumerateArray())
            {
                int sensorId = item.GetProperty("objid").GetInt32();
                string sensorName = item.GetProperty("sensor").GetString();
                string status = item.GetProperty("status").GetString();
                string messageRaw = item.GetProperty("message_raw").GetString();
                string lastValue = item.GetProperty("lastvalue").GetString();
                DateTime currentTime = DateTime.Now;
                sensors.Add(new Sensor
                {
                    DeviceName = deviceName, SensorName = sensorName, SensorId = sensorId, Status = status,
                    MessageRaw = messageRaw, LastValue = lastValue, fetchDateTime = currentTime
                });
            }
        }
        else
        {
            Console.WriteLine($"Error: {response.StatusCode}");
        }

        return sensors;
    }

    public async Task<List<Device>> RefreshSensors(string prtgUrl, string apitoken, List<Device> devices)
    {
        foreach (var device in devices)
        {
            List<Sensor> sensors = await this.FetchSensors(prtgUrl, apitoken, device.Name);
            device.Sensors = sensors;
        }

        return devices;
        
    }

    public async Task<List<Sensor>> FetchSensorsHistoric(string prtgUrl, string apitoken, string deviceName,
        int id, DateTime startDate, DateTime endDate)
    {
        string startDateString = startDate.ToString("yyyy-MM-dd-HH-mm-ss");
        string endDateString = endDate.ToString("yyyy-MM-dd-HH-mm-ss");
        string url =
            $"{prtgUrl}/api/historicdata.json?content=values&output=json&id={id}&sdate={startDateString}&edate={endDateString}&apitoken={apitoken}";
        // outputs the object id and name of the sensor for device DEVICENAME
        var sensors = new List<Sensor>();
        Console.WriteLine(url);
        using HttpClient client = new HttpClient();
        HttpResponseMessage response = await client.GetAsync(url);

        if (response.IsSuccessStatusCode)
        {
            string responseBody = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(responseBody);

            // Console.WriteLine("Sensors retrieved from PRTG:");
            /*
            foreach (var item in jsonDoc.RootElement.GetProperty("sensors").EnumerateArray())
            {
                int sensorId = item.GetProperty("objid").GetInt32();
                string sensorName = item.GetProperty("sensor").GetString();
                string status = item.GetProperty("status").GetString();
                string messageRaw = item.GetProperty("message_raw").GetString();
                string lastValue = item.GetProperty("lastvalue").GetString();
                sensors.Add(new Sensor
                {
                    DeviceName = deviceName, SensorName = sensorName, SensorId = sensorId, Status = status,
                    MessageRaw = messageRaw, LastValue = lastValue
                });
            }*/
        }
        else
        {
            Console.WriteLine($"Error: {response.StatusCode}");
        }

        return sensors;
    }
    
    public Dictionary<string, object> MapSensorToData(Sensor sensor)
    {
        return new Dictionary<string, object>
        {
            { "DeviceName", sensor.DeviceName},
            { "SensorName", sensor.SensorName},
            { "SensorId", sensor.SensorId },
            { "LastValue", sensor.LastValue},
            { "Status", sensor.Status},
            { "MessageRaw", sensor.MessageRaw},
            { "fetchDateTime", sensor.fetchDateTime },
            { "UUID", Guid.NewGuid()}
        };
    }
    
    public Dictionary<string, Type> GetSensorColumnTypes()
    {
        return new Dictionary<string, Type>
        {
            { "DeviceName", typeof(string) },
            { "SensorName", typeof(string) },
            { "SensorId", typeof(int) },
            { "LastValue", typeof(string) },
            { "Status", typeof(string) },
            { "MessageRaw", typeof(string) },
            { "fetchDateTime", typeof(DateTime) }
        };
    }
    
    public async Task InsertSensorsAsync(Device device, string table, Dictionary<string, Type> columns)
    {

        foreach (var sensor in device.Sensors)
        {
            var data = MapSensorToData(sensor);

            foreach (var value in data)
            {
                Console.WriteLine(value);
            }
            
            try
            {
                await _databaseManager.InsertData(table, columns, data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to insert sensor data for {sensor.SensorName}: {ex.Message}");
            }
        }
    }
}




public class Device
{
    public int Id { get; set; }
    public string Name { get; set; }
    public List<Sensor> Sensors { get; set; }
}

public class Sensor
{
    public string DeviceName { get; set; }
    public string SensorName { get; set; }
    public int SensorId { get; set; }
    public string LastValue { get; set; }
    public string Status { get; set; }
    public string MessageRaw { get; set; }
    public DateTime fetchDateTime { get; set; }
}