using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GatewayServer.Module
{
   public class ModuleVersionFile
    {
        public uint nID { get; set; }
        public uint nVersion { get; set; }
        public byte nDivisionID { get; set; }
        public byte nContentID { get; set; }
        public byte nModuleID { get; set; }
        public string szFilename { get; set; }
        public string szPath { get; set; }
        public uint nFileSize { get; set; }
        public byte nFileType { get; set; }
        public uint nFileTypeVersion { get; set; }
        public bool nToBePacked { get; set; }
        public DateTime timeModified { get; set; }
        public byte nValid { get; set; }

    }

   public class ModuleVersion
   {
       public uint nID { get; set; }
       public byte nDivisionID { get; set; }
       public byte nContentID { get; set; }
       public byte nModuleID { get; set; }
       public uint nVersion { get; set; }
       public string szVersion { get; set; }
       public string szDesc { get; set; }
       public byte nValid { get; set; }

   }
}
