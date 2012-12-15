using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Nancy.Authentication.Ntlm.Security
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Handle
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
        public Handle(int dummy)
        {
            LowPart = HighPart = IntPtr.Zero;
        }
    };
}
