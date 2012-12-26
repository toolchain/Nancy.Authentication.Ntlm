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
        /// <returns></returns>
        private static Response Unauthorized()
        {
            var stateId = Guid.NewGuid().ToString();
            Sessions.Add(stateId, new State());

            var response = new Response();
            response.Cookies.Add(new NancyCookie("NTLM", stateId));
            response.StatusCode = HttpStatusCode.Unauthorized;
            response.Headers.Add("WWW-Authenticate", "NTLM");
            return response;
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
                                    // Session stored on server is outdated
                                    var authorization = module.Request.Headers.Authorization;

                                    if (!string.IsNullOrEmpty(authorization) || (authorization.StartsWith("NTLM ")))
                                    {
                                        byte[] token = Convert.FromBase64String(authorization.Substring(5));

                                        var state = new State();

                                        // First eight bytes are header containing NTLMSSP\0 signature
                                        // Next byte contains type of the message recieved.
                                        // Message Type 1 — is initial client's response to server's 401 Unauthorized error.
                                        // Message Type 2 — is the server's response to it. Contains random 8 bytes challenge.
                                        // Message Type 3 — is encrypted password hashes from client ready to server validation.
                                        switch (token[8])
                                        {
                                            case 1:
                                                // Message of type 1 was received
                                                if (EndPoint.IsServerChallengeAcquired(ref token, out state))
                                                {
                                                    Sessions[module.Request.Cookies["NTLM"]] = state;

                                                    Response response = new Response();
                                                    response.StatusCode = HttpStatusCode.Unauthorized;
                                                    response.Headers.Add("WWW-Authenticate", "NTLM " + Convert.ToBase64String(token));
                                                    return response;
                                                }
                                                break;
                                            case 3:
                                                // Message of type 3 was received
                                                state = Sessions[module.Request.Cookies["NTLM"]];

                                                if (EndPoint.IsClientResponseValid(token, ref state))
                                                {
                                                    Type3Message type3Message = new Type3Message(token);

                                                    Sessions[module.Request.Cookies["NTLM"]].ResetHandles();
                                                    Sessions[module.Request.Cookies["NTLM"]].UpdatePresence();
                                                }
                                                else
                                                {
                                                    Sessions.Remove(module.Request.Cookies["NTLM"]);
                                                    return Unauthorized();
                                                }

                                                break;
                                        }
                                    }
                                    else
                                    {
                                        // NTLM Authorization header was not present 
                                        return Unauthorized();
                                    }
                                }
                                else
                                {
                                    Sessions[module.Request.Cookies["NTLM"]].UpdatePresence();
                                }
                            }
                            else
                            {
                                // Session with NTLM cookie identifier is not present
                                return Unauthorized();
                            }
                        }
                        else
                        {
                            // NTLM cookie is not present
                            return Unauthorized();
                        }

                        return null;
                    }));
        }
    }
}