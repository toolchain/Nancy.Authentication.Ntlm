//
// Mono.Security.Cryptography.CapiContext
//
// Authors:
//	Sebastien Pouliot (sebastien@ximian.com)
//
// Copyright (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004 Novell (http://www.novell.com)
//

using System;
using System.Security.Cryptography;

namespace Nancy.Authentication.Ntlm.Cryptography
{
    // we deal with unmanaged resources - they MUST be released after use!
    public class Context : IDisposable 
    {
	    // handles to CryptoAPI - they are 
	    private IntPtr providerHandle;
        
	    private CspParameters cspParams;

	    // has the last call succeded ?
	    private bool lastResult;

	    // Create an instance using the default CSP
	    public Context () : this (null)
	    {
	    }

	    // Create an instance using the specified CSP
	    public Context (CspParameters csp) 
	    {
		    providerHandle = IntPtr.Zero;
		    if (csp == null) {
			    // default parameters
			    cspParams = new CspParameters ();
		    }
		    else {
			    // keep of copy of the parameters
			    cspParams = new CspParameters (csp.ProviderType, csp.ProviderName, csp.KeyContainerName);
			    cspParams.KeyNumber = csp.KeyNumber;
			    cspParams.Flags = csp.Flags;
		    }
		
		    // do not show user interface (CRYPT_SILENT) -  if UI is required then the function fails.
		    uint flags = API.CRYPT_SILENT;
		    if ((cspParams.Flags & CspProviderFlags.UseMachineKeyStore) == CspProviderFlags.UseMachineKeyStore) {
			    flags |= API.CRYPT_MACHINE_KEYSET;
		    }

		    lastResult = API.CryptAcquireContextA (ref providerHandle, cspParams.KeyContainerName,
			    cspParams.ProviderName, cspParams.ProviderType, flags);
		    if (!lastResult) {
			    // key container may not exist
			    flags |= API.CRYPT_NEWKEYSET;
			    lastResult = API.CryptAcquireContextA (ref providerHandle, cspParams.KeyContainerName,
				    cspParams.ProviderName, cspParams.ProviderType, flags);
		    }
	    }

	    ~Context () 
	    {
		    Dispose ();
	    }

	    public int Error {
		    get { return API.GetLastError (); }
	    }

	    public IntPtr Handle {
		    get { return providerHandle; }
	    }

	    public bool Result {
		    get { return lastResult; }
	    }

	    internal bool InternalResult {
		    set { lastResult = value; }
	    }

	    // release unmanaged resources
	    public void Dispose () 
	    {
		    if (providerHandle != IntPtr.Zero) 
            {
			    lastResult = API.CryptReleaseContext (providerHandle, 0);
			    GC.KeepAlive (this);
			    providerHandle = IntPtr.Zero;
			    GC.SuppressFinalize (this);
		    }
	    }
    }
}
