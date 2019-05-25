using Replace.Common.Security;


namespace GatewayServer
{
   internal class ClientData
    {
        public SecurityManager SecurityManager { get; set; }
        public bool Connected { get; set; }
        public CertificationManager CertificationManager { get; set; }

        public ClientData()
        {
            this.SecurityManager = new SecurityManager();
            this.SecurityManager.ChangeIdentity("GatewayServer", 1);

            this.SecurityManager.GenerateSecurity(true, true, true);
        }
    }
}
