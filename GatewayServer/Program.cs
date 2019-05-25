using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using System;
using System.Threading;

namespace GatewayServer
{
   internal class Program
    {
        public const string ModuleName = "GatewayServer";
        private static CertificationManager certificationManager;
        private static CertificationConfig certificationConfig = new CertificationConfig();

        private static Logger logger = LogManager.GetLogger(ModuleName);

        static void Main(string[] args)
        {
            logger.Info("initializing...");
            //setup console 
            Helper.SetupConsole(120, Console.BufferHeight);

            //TODO: Load Config

            certificationManager = new CertificationManager(certificationConfig);

            var asyncClient = new AsyncClient();
            asyncClient.Connect("10.0.0.100", 15880, new ModuleInterface(),certificationManager);

            var asyncServer = new AsyncServer();
            asyncServer.Accept("10.0.0.100", 15779, 5, new ClientInterface(), certificationManager);

            while (true)
            {
                //if (Console.KeyAvailable)
                //{
                //    var keyInfo = Console.ReadKey(true);

                //    if (keyInfo.Key == ConsoleKey.Escape)
                //        break;
                //}

                asyncClient.Tick();
                asyncServer.Tick();

                Thread.Sleep(1);
            }

           // Console.Read();
        }
    }
}
