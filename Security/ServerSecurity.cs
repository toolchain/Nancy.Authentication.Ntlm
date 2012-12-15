using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Nancy.Authentication.Ntlm.Security
{
    public struct SeverSecurity
    {
        public SecurityHandle Credentials;
        public SecurityHandle Context;
    }
}
