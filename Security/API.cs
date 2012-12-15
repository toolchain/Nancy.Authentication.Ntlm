// http://pinvoke.net/default.aspx/secur32/InitializeSecurityContext.html

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Nancy.Authentication.Ntlm.Security
{
    class API
    {
        private const int ISC_REQ_REPLAY_DETECT = 0x00000004;
        private const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        private const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        private const int ISC_REQ_CONNECTION = 0x00000800;

        public const int StandardContextAttributes = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONNECTION;
        public const int SecurityNativeDataRepresentation = 0x10;
        public const int MaximumTokenSize = 12288;
        public const int SecurityCredentialsInbound = 1;
        public const int SuccessfulResult = 0;
        public const int IntermediateResult = 0x90312;

        public static bool IsServerChallengeAcquired(byte[] message, out State serverState)
        {
            BufferDesciption ClientToken = new BufferDesciption(message);

            try
            {
                Integer NewLifeTime = new Integer(0);
                uint NewContextAttribute = 0;
                int result;

                serverState = new State()
                {
                    Credentials = new Handle(0),
                    Context = new Handle(0),
                    Token = new BufferDesciption(API.MaximumTokenSize)
                };

                result = AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name,
                    "NTLM",
                    API.SecurityCredentialsInbound,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    ref serverState.Credentials,
                    ref NewLifeTime);

                if (result != API.SuccessfulResult)
                {
                    // Credentials acquire operation failed.
                    return false;
                }

                result = AcceptSecurityContext(ref serverState.Credentials, // [in] handle to the credentials
                    IntPtr.Zero,                                            // [in/out] handle of partially formed context.  Always NULL the first time through
                    ref ClientToken,                                        // [in] pointer to the input buffers
                    API.StandardContextAttributes,                          // [in] required context attributes
                    API.SecurityNativeDataRepresentation,                   // [in] data representation on the target
                    out serverState.Context,                                // [in/out] receives the new context handle    
                    out serverState.Token,                                  // [in/out] pointer to the output buffers
                    out NewContextAttribute,                                // [out] receives the context attributes        
                    out NewLifeTime);                                       // [out] receives the life span of the security context

                if (result != API.IntermediateResult)
                {
                    // Client challenge issue operation failed.
                    return false;
                }
            }
            finally
            {
                ClientToken.Dispose();
            }

            return true;
        }

        public static bool IsClientResponseValid(byte[] message, ref State serverState)
        {
            BufferDesciption ClientToken = new BufferDesciption(message);

            try
            {
                Integer NewLifeTime = new Integer(0);
                uint NewContextAttribute = 0;
                int result;

                result = API.AcceptSecurityContext(ref serverState.Credentials, // [in] handle to the credentials
                    ref serverState.Context,                                    // [in/out] handle of partially formed context.  Always NULL the first time through
                    ref ClientToken,                                            // [in] pointer to the input buffers
                    API.StandardContextAttributes,                              // [in] required context attributes
                    API.SecurityNativeDataRepresentation,                       // [in] data representation on the target
                    out serverState.Context,                                    // [in/out] receives the new context handle    
                    out serverState.Token,                                      // [in/out] pointer to the output buffers
                    out NewContextAttribute,                                    // [out] receives the context attributes        
                    out NewLifeTime);                                           // [out] receives the life span of the security context

                if (result != API.SuccessfulResult)
                {
                    return false;
                }
            }
            finally
            {
                ClientToken.Dispose();
            }

            return true;
        }

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int AcquireCredentialsHandle(
            string pszPrincipal,                            //SEC_CHAR*
            string pszPackage,                              //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,                       //_LUID AuthenticationID,//pvLogonID, //PLUID
            IntPtr pAuthData,                               //PVOID
            int pGetKeyFn,                                  //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument,                        //PVOID
            ref Handle phCredential,                        //SecHandle //PCtxtHandle ref
            ref Integer ptsExpiry);                         //PTimeStamp //TimeStamp ref

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int AcceptSecurityContext(ref Handle phCredential,
            IntPtr phContext,
            ref BufferDesciption pInput,
            uint fContextReq,
            uint TargetDataRep,
            out Handle phNewContext,
            out BufferDesciption pOutput,
            out uint pfContextAttr,                         //managed ulong == 64 bits!!!
            out Integer ptsTimeStamp);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int AcceptSecurityContext(ref Handle phCredential,
            ref Handle phContext,
            ref BufferDesciption pInput,
            uint fContextReq,
            uint TargetDataRep,
            out Handle phNewContext,
            out BufferDesciption pOutput,
            out uint pfContextAttr,                         //managed ulong == 64 bits!!!
            out Integer ptsTimeStamp);
    }
}
