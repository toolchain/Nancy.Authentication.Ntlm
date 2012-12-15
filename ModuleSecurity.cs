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
        public static Dictionary<string, Sever> Contexts = new Dictionary<string, Sever>();

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
                                byte[] message = Convert.FromBase64String(AuthorizationString.Substring(5));

                                var server = new Sever()
                                {
                                    Credentials = new Handle(0),
                                    Context = new Handle(0)
                                };

                                Integer NewLifeTime = new Integer(0);
                                BufferDesciption ServerToken = new BufferDesciption(API.MaximumTokenSize);
                                BufferDesciption ClientToken = new BufferDesciption(message);

                                if (API.AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name, 
                                        "NTLM", 
                                        API.SECPKG_CRED_INBOUND,
                                        IntPtr.Zero, 
                                        IntPtr.Zero, 
                                        0, 
                                        IntPtr.Zero,
                                        ref server.Credentials, 
                                        ref NewLifeTime) != API.SuccessfulResult)
                                {
                                    throw new Exception("Couldn't acquire server credentials handle!!!");
                                }

                                Response response = new Response();
                                
                                int ss = -1;

                                switch (message[8])
                                {
                                    case 1:
                                        // Message of type 1 was received
                                        try
                                        {
                                            uint uNewContextAttr = 0;

                                            ss = API.AcceptSecurityContext(ref server.Credentials,  // [in] handle to the credentials
                                                IntPtr.Zero,                                        // [in/out] handle of partially formed context.  Always NULL the first time through
                                                ref ClientToken,                                    // [in] pointer to the input buffers
                                                API.StandardContextAttributes,                      // [in] required context attributes
                                                API.SecurityNativeDataRepresentation,               // [in] data representation on the target
                                                out server.Context,                                 // [in/out] receives the new context handle    
                                                out ServerToken,                                    // [in/out] pointer to the output buffers
                                                out uNewContextAttr,                                // [out] receives the context attributes        
                                                out NewLifeTime);                                   // [out] receives the life span of the security context

                                            var contextId = Guid.NewGuid().ToString();

                                            Contexts.Add(contextId, server);

                                            response.Cookies.Add(new NancyCookie("NTLM", contextId));
                                            response.StatusCode = HttpStatusCode.Unauthorized;
                                            response.Headers.Add("Connection", "Keep-Alive");
                                            response.Headers.Add("WWW-Authenticate", "NTLM " + Convert.ToBase64String(ServerToken.GetSecBufferByteArray()));
                                            return response;
                                        }
                                        finally
                                        {
                                            ClientToken.Dispose();
                                            ServerToken.Dispose();
                                        }

                                    case 3:
                                        // Message of type 3 was received
                                        try
                                        {
                                            server = Contexts[module.Request.Cookies["NTLM"]];
                                            Contexts.Remove(module.Request.Cookies["NTLM"]);

                                            uint uNewContextAttr = 0;

                                            ss = API.AcceptSecurityContext(ref server.Credentials,  // [in] handle to the credentials
                                                ref server.Context,                                 // [in/out] handle of partially formed context.  Always NULL the first time through
                                                ref ClientToken,                                    // [in] pointer to the input buffers
                                                API.StandardContextAttributes,                      // [in] required context attributes
                                                API.SecurityNativeDataRepresentation,               // [in] data representation on the target
                                                out server.Context,                                 // [in/out] receives the new context handle    
                                                out ServerToken,                                    // [in/out] pointer to the output buffers
                                                out uNewContextAttr,                                // [out] receives the context attributes        
                                                out NewLifeTime);                                   // [out] receives the life span of the security context

                                            if (ss != API.SuccessfulResult)
                                            {
                                                return Unauthorized();
                                            }
                                            else
                                            {
                                                Type3Message type3Message = new Type3Message(ClientToken.GetSecBufferByteArray());
                                                module.Context.Response.Headers.Add("Authorization", "NTLM " + Convert.ToBase64String(ClientToken.GetSecBufferByteArray()));
                                                module.Context.Response.StatusCode = HttpStatusCode.OK;
                                            }
                                        }
                                        catch (KeyNotFoundException)
                                        {
                                            return Unauthorized();
                                        }
                                        finally
                                        {
                                            ClientToken.Dispose();
                                            ServerToken.Dispose();
                                        }

                                        break;
                                }
                            }
                        }
                        return null;
                    }));
        }
    }
}