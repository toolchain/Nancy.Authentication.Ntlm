using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Nancy.Authentication.Ntlm.Security
{
    public struct State
    {
        public Common.SecurityHandle Credentials;
        public Common.SecurityHandle Context;
        public Common.SecurityBufferDesciption Token;
    }
}
