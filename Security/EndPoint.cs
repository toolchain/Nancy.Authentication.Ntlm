// http://pinvoke.net/default.aspx/secur32/InitializeSecurityContext.html

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Nancy.Authentication.Ntlm.Security
{
    class EndPoint
    {
        public static bool IsServerChallengeAcquired(ref byte[] message, out State serverState)
        {
            Common.SecurityBufferDesciption ClientToken = new Common.SecurityBufferDesciption(message);
            Common.SecurityBufferDesciption ServerToken = new Common.SecurityBufferDesciption(Common.MaximumTokenSize);

            try
            {
                int result;

                serverState = new State()
                {
                    Credentials = new Common.SecurityHandle(0),
                    Context = new Common.SecurityHandle(0),
                };

                result = AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name,
                    "NTLM",
                    Common.SecurityCredentialsInbound,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    ref serverState.Credentials,
                    ref Common.NewLifeTime);

                if (result != Common.SuccessfulResult)
                {
                    // Credentials acquire operation failed.
                    return false;
                }

                result = AcceptSecurityContext(ref serverState.Credentials, // [in] handle to the credentials
                    IntPtr.Zero,                                            // [in/out] handle of partially formed context.  Always NULL the first time through
                    ref ClientToken,                                        // [in] pointer to the input buffers
                    Common.StandardContextAttributes,                       // [in] required context attributes
                    Common.SecurityNativeDataRepresentation,                // [in] data representation on the target
                    out serverState.Context,                                // [in/out] receives the new context handle    
                    out ServerToken,                                        // [in/out] pointer to the output buffers
                    out Common.NewContextAttributes,                        // [out] receives the context attributes        
                    out Common.NewLifeTime);                                // [out] receives the life span of the security context

                if (result != Common.IntermediateResult)
                {
                    // Client challenge issue operation failed.
                    return false;
                }
            }
            finally
            {
                message = ServerToken.GetSecBufferByteArray();

                ClientToken.Dispose();
                ServerToken.Dispose();
            }

            return true;
        }

        public static bool IsClientResponseValid(byte[] message, ref State serverState)
        {
            Common.SecurityBufferDesciption ClientToken = new Common.SecurityBufferDesciption(message);
            Common.SecurityBufferDesciption ServerToken = new Common.SecurityBufferDesciption(Common.MaximumTokenSize);

            try
            {
                int result;

                result = AcceptSecurityContext(ref serverState.Credentials, // [in] handle to the credentials
                    ref serverState.Context,                                // [in/out] handle of partially formed context.  Always NULL the first time through
                    ref ClientToken,                                        // [in] pointer to the input buffers
                    Common.StandardContextAttributes,                       // [in] required context attributes
                    Common.SecurityNativeDataRepresentation,                // [in] data representation on the target
                    out serverState.Context,                                // [in/out] receives the new context handle    
                    out ServerToken,                                        // [in/out] pointer to the output buffers
                    out Common.NewContextAttributes,                        // [out] receives the context attributes        
                    out Common.NewLifeTime);                                // [out] receives the life span of the security context

                if (result != Common.SuccessfulResult)
                {
                    return false;
                }
            }
            finally
            {
                ClientToken.Dispose();
                ServerToken.Dispose();
            }

            return true;
        }

        #region Native calls to secur32.dll

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int AcquireCredentialsHandle(
            string pszPrincipal,                            //SEC_CHAR*
            string pszPackage,                              //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,                       //_LUID AuthenticationID,//pvLogonID, //PLUID
            IntPtr pAuthData,                               //PVOID
            int pGetKeyFn,                                  //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument,                        //PVOID
            ref Common.SecurityHandle phCredential,                        //SecHandle //PCtxtHandle ref
            ref Common.SecurityInteger ptsExpiry);                         //PTimeStamp //TimeStamp ref

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int AcceptSecurityContext(ref Common.SecurityHandle phCredential,
            IntPtr phContext,
            ref Common.SecurityBufferDesciption pInput,
            uint fContextReq,
            uint TargetDataRep,
            out Common.SecurityHandle phNewContext,
            out Common.SecurityBufferDesciption pOutput,
            out uint pfContextAttr,                         //managed ulong == 64 bits!!!
            out Common.SecurityInteger ptsTimeStamp);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int AcceptSecurityContext(ref Common.SecurityHandle phCredential,
            ref Common.SecurityHandle phContext,
            ref Common.SecurityBufferDesciption pInput,
            uint fContextReq,
            uint TargetDataRep,
            out Common.SecurityHandle phNewContext,
            out Common.SecurityBufferDesciption pOutput,
            out uint pfContextAttr,                         //managed ulong == 64 bits!!!
            out Common.SecurityInteger ptsTimeStamp);

        #endregion
    }
}
