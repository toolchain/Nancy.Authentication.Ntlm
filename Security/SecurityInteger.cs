using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Nancy.Authentication.Ntlm.Security
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityInteger
    {
        public uint LowPart;
        public int HighPart;
        public SecurityInteger(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };
}
