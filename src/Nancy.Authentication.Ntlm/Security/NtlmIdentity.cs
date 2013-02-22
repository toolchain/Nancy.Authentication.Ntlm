namespace Nancy.Authentication.Ntlm.Security
{
    using Nancy.Security;
    using System;
    using System.Collections.Generic;

    public class NtlmIdentity : INtlmIdentity
    {
        public IEnumerable<string> Claims { get; set; }

        public string UserName { get; set; }
        public string Domain { get; set; }
        public Common.NtlmFlags Flags { get; set; }
    }
}
