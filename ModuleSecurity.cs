using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;

using Nancy;
using Nancy.Authentication.Ntlm.Protocol;
using System.DirectoryServices.AccountManagement;
using SSPITest;
using Nancy.Session;
using Nancy.Cookies;
using System.IO;
using Nancy.Json;

namespace Nancy.Authentication.Ntlm
{
    public static class ModuleSecurity
    {
        public static Dictionary<string, SeverSecurity> Contexts = new Dictionary<string, SeverSecurity>();

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

                                SeverSecurity serverSecurity = new SeverSecurity()
                                {
                                    Credentials = new SecurityHandle(0),
                                    Context = new SecurityHandle(0)
                                };

                                SecurityInteger NewLifeTime = new SecurityInteger(0);
                                SecurityBufferDesciption ServerToken = new SecurityBufferDesciption(SspiApi.MaximumTokenSize);
                                SecurityBufferDesciption ClientToken = new SecurityBufferDesciption(message);

                                if (SspiApi.AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name, 
                                        "NTLM", 
                                        SspiApi.SECPKG_CRED_INBOUND,
                                        IntPtr.Zero, 
                                        IntPtr.Zero, 
                                        0, 
                                        IntPtr.Zero,
                                        ref serverSecurity.Credentials, 
                                        ref NewLifeTime) != SspiApi.SEC_E_OK)
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

                                            ss = SspiApi.AcceptSecurityContext(ref serverSecurity.Credentials,   // [in] handle to the credentials
                                                IntPtr.Zero,                                                        // [in/out] handle of partially formed context.  Always NULL the first time through
                                                ref ClientToken,                                                    // [in] pointer to the input buffers
                                                SspiApi.StandardContextAttributes,                               // [in] required context attributes
                                                SspiApi.SecurityNativeDataRepresentation,                        // [in] data representation on the target
                                                out serverSecurity.Context,                                         // [in/out] receives the new context handle    
                                                out ServerToken,                                                    // [in/out] pointer to the output buffers
                                                out uNewContextAttr,                                                // [out] receives the context attributes        
                                                out NewLifeTime);                                                   // [out] receives the life span of the security context

                                            var contextId = Guid.NewGuid().ToString();

                                            Contexts.Add(contextId, serverSecurity);

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
                                            serverSecurity = Contexts[module.Request.Cookies["NTLM"]];
                                            Contexts.Remove(module.Request.Cookies["NTLM"]);

                                            uint uNewContextAttr = 0;

                                            ss = SspiApi.AcceptSecurityContext(ref serverSecurity.Credentials,  // [in] handle to the credentials
                                                ref serverSecurity.Context,                                     // [in/out] handle of partially formed context.  Always NULL the first time through
                                                ref ClientToken,                                                // [in] pointer to the input buffers
                                                SspiApi.StandardContextAttributes,                              // [in] required context attributes
                                                SspiApi.SecurityNativeDataRepresentation,                       // [in] data representation on the target
                                                out serverSecurity.Context,                                     // [in/out] receives the new context handle    
                                                out ServerToken,                                                // [in/out] pointer to the output buffers
                                                out uNewContextAttr,                                            // [out] receives the context attributes        
                                                out NewLifeTime);                                               // [out] receives the life span of the security context

                                            if (ss != SspiApi.SEC_E_OK)
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