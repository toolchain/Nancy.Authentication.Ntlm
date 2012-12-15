using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Nancy.Authentication.Ntlm.Security
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Integer
    {
        public uint LowPart;
        public int HighPart;
        public Integer(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };
}
