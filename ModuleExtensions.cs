using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;

using Nancy;
using Nancy.Cookies;

using Nancy.Authentication.Ntlm.Protocol;
using Nancy.Authentication.Ntlm.Security;

namespace Nancy.Authentication.Ntlm
{
    public static class ModuleExtensions
    {
        internal static Dictionary<string, State> Sessions = new Dictionary<string, State>();

        /// <summary>
        /// Sends 401 Unauthorized response to browser
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private static Response SendUnauthorized(byte[] token)
        {
            var response = new Response();
            var authorization = string.Empty;

            if (token == null)
            {
                var stateId = Guid.NewGuid().ToString();
                Sessions.Add(stateId, new State());
                response.Cookies.Add(new NancyCookie("NTLM", stateId));
            }
            else
            {
                authorization = string.Concat(" ", Convert.ToBase64String(token));
            }
            
            response.StatusCode = HttpStatusCode.Unauthorized;
            response.Headers.Add("WWW-Authenticate", string.Concat("NTLM", authorization));
            return response;
        }

        /// <summary>
        /// Aquires token from authorization string
        /// </summary>
        /// <param name="authorization"></param>
        /// <returns></returns>
        private static byte[] AquireToken(string authorization)
        {
            if (!string.IsNullOrEmpty(authorization) || (authorization.StartsWith("NTLM ")))
            {
                return Convert.FromBase64String(authorization.Substring(5)); ;
            }
            return null;
        }

        /// <summary>
        /// Cleans up old sessions
        /// </summary>
        private static void CleanupSessions()
        {
            var random = new Random();

            if (random.Next(0, 10) % 3 == 0)
            {
                foreach (var session in Sessions.Where(x => x.Value.isOlder(3600)))
                {
                    Sessions.Remove(session.Key);
                }
            }
        }

        public static void RequiresNtlmAuthentication(this NancyModule module)
        {
            module.Before.AddItemToEndOfPipeline(
                new PipelineItem<Func<NancyContext, Response>>(
                    "RequiresNtlmAuthentication",
                    ctx =>
                    {
                        if (module.Request.Cookies.ContainsKey("NTLM"))
                        {
                            // NTLM cookie is present
                            if (Sessions.ContainsKey(module.Request.Cookies["NTLM"]))
                            {
                                // Session with NTLM cookie identifier is present
                                if (Sessions[module.Request.Cookies["NTLM"]].isOlder(3600))
                                {
                                    // Session stored on server is outdated, so authorization process need to take place
                                    var token = AquireToken(module.Request.Headers.Authorization);

                                    if (token != null)
                                    {
                                        var state = Sessions[module.Request.Cookies["NTLM"]];

                                        // First eight bytes are header containing NTLMSSP\0 signature
                                        // Next byte contains type of the message recieved.
                                        // Message Type 1 — is initial client's response to server's 401 Unauthorized error.
                                        // Message Type 2 — is the server's response to it. Contains random 8 bytes challenge.
                                        // Message Type 3 — is encrypted password hashes from client ready to server validation.
                                        switch (token[8])
                                        {
                                            case 1:
                                                #region Message of type 1 was received
                                                if (EndPoint.IsServerChallengeAcquired(ref token, out state))
                                                {
                                                    Sessions[module.Request.Cookies["NTLM"]] = state;
                                                    return SendUnauthorized(token);
                                                }

                                                break;
                                                #endregion
                                            case 3:
                                                #region Message of type 3 was received
                                                if (EndPoint.IsClientResponseValid(token, ref state))
                                                {
                                                    Type3Message type3Message = new Type3Message(token);

                                                    Sessions[module.Request.Cookies["NTLM"]].ResetHandles();
                                                    Sessions[module.Request.Cookies["NTLM"]].UpdatePresence();

                                                    // Authorization successful 
                                                    return null;
                                                }
                                                else
                                                {
                                                    Sessions.Remove(module.Request.Cookies["NTLM"]);
                                                }

                                                break;
                                                #endregion
                                        }
                                    }
                                }
                                else
                                {
                                    // Normal behaviour
                                    CleanupSessions();
                                    Sessions[module.Request.Cookies["NTLM"]].UpdatePresence();

                                    // Operation successful 
                                    return null;
                                }
                            }
                        }

                        return SendUnauthorized(null);
                    }));
        }
    }
}