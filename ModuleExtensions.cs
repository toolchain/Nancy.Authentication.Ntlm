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
        public static Dictionary<string, State> Unfinished = new Dictionary<string, State>();

        private static Response Unauthorized()
        {
            var response = new Response();
            response.StatusCode = HttpStatusCode.Unauthorized;
            response.Headers.Add("Connection", "Keep-Alive");
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
                        if ((module.Context.CurrentUser == null) || string.IsNullOrEmpty(module.Context.CurrentUser.UserName))
                        {
                            string AuthorizationString = module.Request.Headers.Authorization;
                            if (string.IsNullOrEmpty(AuthorizationString) || (!AuthorizationString.StartsWith("NTLM ")))
                            {
                                return Unauthorized();
                            }
                            else
                            {
                                byte[] token = Convert.FromBase64String(AuthorizationString.Substring(5));

                                State authenticationState = new State();

                                try
                                {
                                    // First eight bytes are header containing NTLMSSP\0 signature
                                    // Next byte contains type of the message recieved.
                                    // Message Type 1 — is initial client's response to server's 401 Unauthorized error.
                                    // Message Type 2 — is the server's response to it. Contains random 8 bytes challenge.
                                    // Message Type 3 — is encrypted password hashes from client ready to server validation.
                                    switch (token[8])
                                    {
                                        case 1:
                                            // Message of type 1 was received
                                            if (EndPoint.IsServerChallengeAcquired(ref token, out authenticationState))
                                            {
                                                var stateId = Guid.NewGuid().ToString();
                                                Unfinished.Add(stateId, authenticationState);

                                                Response response = new Response();
                                                response.Cookies.Add(new NancyCookie("NTLM", stateId));
                                                response.StatusCode = HttpStatusCode.Unauthorized;
                                                response.Headers.Add("Connection", "Keep-Alive");
                                                response.Headers.Add("WWW-Authenticate", "NTLM " + Convert.ToBase64String(authenticationState.Token.GetSecBufferByteArray()));
                                                return response;
                                            }
                                            break;
                                        case 3:
                                            // Message of type 3 was received
                                            authenticationState = Unfinished[module.Request.Cookies["NTLM"]];
                                            Unfinished.Remove(module.Request.Cookies["NTLM"]);

                                            if (EndPoint.IsClientResponseValid(token, ref authenticationState))
                                            {
                                                Type3Message type3Message = new Type3Message(token);
                                                // module.Context.Response.Headers.Add("Authorization", "NTLM " + Convert.ToBase64String(clientMessage));
                                                // module.Context.Response.StatusCode = HttpStatusCode.OK;
                                            }
                                            else
                                            {
                                                return Unauthorized();
                                            }

                                            break;
                                    }
                                }
                                catch (KeyNotFoundException)
                                {
                                    return Unauthorized();
                                }
                                finally
                                {
                                    authenticationState.Token.Dispose();
                                }
                            }
                        }
                        return null;
                    }));
        }
    }
}