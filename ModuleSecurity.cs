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
    public static class ModuleSecurity
    {
        public static Dictionary<string, ServerState> Unfinished = new Dictionary<string, ServerState>();

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
                                byte[] clientMessage = Convert.FromBase64String(AuthorizationString.Substring(5));

                                ServerState serverState = new ServerState();
                                Response response = new Response();

                                try
                                {
                                    switch (clientMessage[8])
                                    {
                                        case 1:
                                            // Message of type 1 was received
                                            var stateId = Guid.NewGuid().ToString();
                                            API.AcquireServerToken(clientMessage, out serverState);

                                            Unfinished.Add(stateId, serverState);

                                            response.Cookies.Add(new NancyCookie("NTLM", stateId));
                                            response.StatusCode = HttpStatusCode.Unauthorized;
                                            response.Headers.Add("Connection", "Keep-Alive");
                                            response.Headers.Add("WWW-Authenticate", "NTLM " + Convert.ToBase64String(serverState.Token.GetSecBufferByteArray()));
                                            
                                            return response;
                                        case 3:
                                            // Message of type 3 was received
                                            serverState = Unfinished[module.Request.Cookies["NTLM"]];
                                            Unfinished.Remove(module.Request.Cookies["NTLM"]);

                                            if (API.ValidateClientToken(clientMessage, serverState))
                                            {
                                                return Unauthorized();
                                            }
                                            else
                                            {
                                                Type3Message type3Message = new Type3Message(clientMessage);
                                                module.Context.Response.Headers.Add("Authorization", "NTLM " + Convert.ToBase64String(clientMessage));
                                                module.Context.Response.StatusCode = HttpStatusCode.OK;
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
                                    serverState.Token.Dispose();
                                }
                            }
                        }
                        return null;
                    }));
        }
    }
}