using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Nancy.Authentication.Ntlm.Security
{
    /// <summary>
    /// Status of authenticated session
    /// </summary>
    internal class State
    {
        public State()
        {
            this.Credentials = new Common.SecurityHandle(0);
            this.Context = new Common.SecurityHandle(0);

            this.LastSeen = DateTime.MinValue;
        }

        /// <summary>
        /// Credentials used to validate NTLM hashes
        /// </summary>
        public Common.SecurityHandle Credentials;

        /// <summary>
        /// Context will be used to validate HTLM hashes
        /// </summary>
        public Common.SecurityHandle Context;

        /// <summary>
        /// Timestamp needed to calculate validity of the authenticated session
        /// </summary>
        public DateTime LastSeen;

        public bool isOlder(int seconds)
        {
            return (this.LastSeen.AddSeconds(seconds) < DateTime.UtcNow) ? true : false;
        }

        public void ResetHandles()
        {
            this.Credentials.Reset();
            this.Context.Reset();
        }

        public void UpdatePresence()
        {
            this.LastSeen = DateTime.UtcNow;
        }
    }
}
