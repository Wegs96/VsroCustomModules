using GatewayServer.Module.Config;
using Replace.Common.Security;

namespace GatewayServer.Module
{
   internal class ModuleData
    {
        public SecurityManager SecurityManager { get; set; }
        public bool Connected { get; set; }
        public CertificationManager CertificationManager { get; set; }

        public ModuleData()
        {
            this.SecurityManager = new SecurityManager();
            this.SecurityManager.ChangeIdentity("GatewayServer", 0);
            //we don't need to GenerateSecurity for Modules
            //  this.SecurityManager.GenerateSecurity(true, true, true);
        }
    }
}
