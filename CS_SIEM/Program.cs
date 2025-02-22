// See https://aka.ms/new-console-template for more information

#define DISABLE_DATABASE_TEST
#define DISABLE_SNMP_TEST

using System.Diagnostics;
using System.Net;
using CS_DatabaseManager;
using static CS_SIEM.SnmpPollSender;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Cassandra;
using Microsoft.Extensions.Logging;
namespace CS_SIEM;

public static class Program
{
    private static short _counter;


    public static async Task Main(string[] args)
    {
    }
}
