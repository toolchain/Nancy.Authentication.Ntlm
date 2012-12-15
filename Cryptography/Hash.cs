//
// Mono.Security.Cryptography.CapiHash
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
    public class Hash : IDisposable {

	    private Context context;
	    private IntPtr handle;
	    private uint hashSize;

	    public Hash (int hashAlgorithm) 
	    {
		    context = new Context ();
		    Initialize (hashAlgorithm);
	    }

	    public Hash (Context ctx, int hashAlgorithm) 
	    {
		    context = ctx;
		    Initialize (hashAlgorithm);
	    }

	    public Hash (CspParameters cspParams, int hashAlgorithm) 
	    {
		    context = new Context (cspParams);
		    Initialize (hashAlgorithm);
	    }

	    ~Hash () 
	    {
		    Dispose ();
	    }

	    public IntPtr Handle 
        {
		    get { return handle; }
	    }

	    public int HashSize 
        {
		    get { return (int) hashSize; }
	    }

	    public void Initialize (int algo) 
	    {
		    if (context != null) {
			    context.InternalResult = API.CryptCreateHash (context.Handle, (uint)algo, IntPtr.Zero, 0, ref handle);
			    hashSize = 0;
			    if (context.Result)
				    context.InternalResult = API.CryptGetHashParam (handle, API.HP_HASHVAL, null, ref hashSize, 0);
			    GC.KeepAlive (this);
		    }
	    }

	    public void Dispose () 
	    {
		    if (handle != IntPtr.Zero) {
			    API.CryptDestroyHash (handle);
			    context.Dispose ();
			    GC.KeepAlive (this);
			    handle = IntPtr.Zero;
			    GC.SuppressFinalize (this);
		    }
	    }

	    // FIXME: calling this function 1,000,000 times (with a single character)
	    // is a good way to lose time (and hung NUnit)
	    // TODO: find the bug that hang NUnit
	    // TODO: optimize the function to call CryptHashData less often (bufferize)
	    public void HashCore (byte[] data, int start, int length) 
	    {
		    byte[] toBeHashed = data;
		    if (start != 0) {
			    toBeHashed = new byte [length];
			    Array.Copy (data, start, toBeHashed, 0, length);
		    }
		    context.InternalResult = API.CryptHashData (handle, toBeHashed, (uint)length, 0);
		    GC.KeepAlive (this);
	    }

	    public byte[] HashFinal () 
	    {
		    byte[] hash = new byte [hashSize];
		    context.InternalResult = API.CryptGetHashParam (handle, API.HP_HASHVAL, hash, ref hashSize, 0);
		    GC.KeepAlive (this);
		    return hash;
	    }
    }
}
