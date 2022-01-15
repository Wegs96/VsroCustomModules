using System.Net;
using GatewayServer.Module.Config;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using Replace.Common.Security;

namespace GatewayServer.Client
{
   internal class ClientData
    {
        public SecurityManager SecurityManager { get; set; }
        public bool Connected { get; set; }
        public CertificationManager CertificationManager { get; set; }

        public string Username { get; set; }
        public string Password { get; set; }

        public string Md5Password()
        {
            return Helper.CalculateMD5Hash(Password);
        }
        public uint Jid { get; set; }
        public byte SecPrimary { get; set; }
        public byte SecContent { get; set; }
        public ushort AccPlayTime { get; set; }
        public uint LatestUpdateTimeToPlayTime { get; set; }
        public uint AgentToken { get; set; }
        public IPEndPoint RemoteIpEndPoint { get; set; }
        public AsyncContext Context { get; set; }
        public ClientData()
        {
            this.SecurityManager = new SecurityManager();
            this.SecurityManager.ChangeIdentity("GatewayServer", 1);

            this.SecurityManager.GenerateSecurity(true, true, true);
        }
    }
}
