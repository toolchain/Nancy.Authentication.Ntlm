﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Nancy.Authentication.Ntlm.Security
{
    public struct ServerState
    {
        public Handle Credentials;
        public Handle Context;
    }
}