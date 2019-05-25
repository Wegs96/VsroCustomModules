using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Replace.Common.Certification
{
    [DebuggerDisplay("{_Subject} -> {_Article} -> {_EditDate}")]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class Notice : ICertificationRow
    {
        #region Fields

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        private string _Subject;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        private string _Article;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        private DateTime _EditDate;


        #endregion Fields

        #region Properties

        public string Subject { get { return _Subject; } private set { _Subject = value; } }
        public string Article { get { return _Article; } private set { _Article = value; } }
        public DateTime EditDate { get { return _EditDate; } private set { _EditDate = value; } }

        #endregion Properties
    }

}
