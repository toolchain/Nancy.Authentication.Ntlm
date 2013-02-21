namespace Nancy.Authentication.Ntlm.Security
{
    using Nancy.Security;
    using System;

    public interface INtlmIdentity : IUserIdentity
    {
        string Domain { get; set; }
        Common.NtlmFlags Flags { get; set; }
    }
}
