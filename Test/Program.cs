using System.Diagnostics;
using Cassandra;

namespace Test;

class Program
{
    static void Main(string[] args)
    {
        const int iterations = 1_000_000; // Number of iterations for benchmarking
        DateTime now = DateTime.Parse("2025-10-01 12:45:21.345632131");

        // Benchmark Property-Based Approach
        Stopwatch stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            PropertyBased(now);
        }

        stopwatch.Stop();
        Console.WriteLine($"Property-Based Approach: {stopwatch.ElapsedMilliseconds} ms");
        // Benchmark String-Based Approach
        stopwatch.Restart();
        for (int i = 0; i < iterations; i++)
        {
            StringBased(now);
        }

        stopwatch.Stop();
        Console.WriteLine($"String-Based Approach: {stopwatch.ElapsedMilliseconds} ms");

        int year = now.Year;
        int month = now.Month;
        int day = now.Day;
        int hour = now.Hour;
        int minute = now.Minute;
        int second = now.Second;
        int milli = now.Millisecond;
        int micro = now.Microsecond;
        int nanosecond = now.Nanosecond;

        var ld = new LocalDate(year, month, day);
        var lt = new LocalTime(hour, minute, second, milli * 1000000 + micro * 1000);
        Console.WriteLine(ld + " " + lt);
    }

    static void PropertyBased(DateTime dateTime)
    {
        var ld = new LocalDate(2025, 1, 10);
        var lt = new LocalTime(12, 12, 4, 123 * 1000000 + 123 * 1000);
    }

    static void StringBased(DateTime dateTime)
    {
        var ld = LocalDate.Parse("2025-01-10");
        var lt = LocalTime.Parse("12:12:04.123123");
    }
}