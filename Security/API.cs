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

        public static void AcquireCredentialsHandle(WindowsIdentity identity, ServerState state)
        {
            Integer NewLifeTime = new Integer(0);
            if (AcquireCredentialsHandle(identity.Name,
                "NTLM",
                API.SecurityCredentialsInbound,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                ref state.Credentials,
                ref NewLifeTime) != API.SuccessfulResult)
            {
                throw new Exception("Couldn't acquire server credentials handle!!!");
            }
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
        public static extern int AcceptSecurityContext(ref Handle phCredential,
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
