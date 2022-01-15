using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using System;
using System.Threading;
using GatewayServer.Client;
using GatewayServer.Module;
using GatewayServer.Module.Config;

namespace GatewayServer
{
   internal class Program
    {
        public static bool Certificated { get; set; }
        public static AsyncServer AsyncServer { get; set; }
        public static uint test = 0;
        public const string ModuleName = "GatewayServer";
        private static CertificationManager _certificationManager;
        private static readonly CertificationConfig CertificationConfig = new CertificationConfig();

        private static readonly Logger Logger = LogManager.GetLogger(ModuleName);

        static void Main(string[] args)
        {
            Logger.Info("initializing...");
            //setup console 
            Helper.SetupConsole(120, Console.BufferHeight);

            _certificationManager = new CertificationManager(CertificationConfig);

            // var asyncClient = new AsyncClient();
            //asyncClient.Connect("10.0.0.100", 15880, new ModuleInterface(),_certificationManager);

            var asyncServer = new AsyncServer();
            asyncServer.Accept("127.0.0.1", 5001, 5, new ClientInterface(), _certificationManager);

            while (true)
            {
                //if (Console.KeyAvailable)
                //{
                //    var keyInfo = Console.ReadKey(true);

                //    if (keyInfo.Key == ConsoleKey.Escape)
                //        break;
                //}

                //asyncClient.Tick();
                if(Certificated)
                     AsyncServer.Tick();

                Thread.Sleep(10);
            }

           // Console.Read();
        }
    }
}
