//
// Nancy.Authentication.Ntlm.Protocol.Type3Message - Authentication
//
// Author:
//	Sebastien Pouliot <sebastien@ximian.com>
//
// (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004 Novell, Inc (http://www.novell.com)
//
// References
// a.	NTLM Authentication Scheme for HTTP, Ronald Tschalär
//	http://www.innovation.ch/java/ntlm.html
// b.	The NTLM Authentication Protocol, Copyright © 2003 Eric Glass
//	http://davenport.sourceforge.net/ntlm.html
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

namespace Nancy.Authentication.Ntlm.Protocol 
{
    using System;
    using System.Text;
    using Nancy.Authentication.Ntlm.Security;

	public class Type3Message : MessageBase 
    {
		public Type3Message (byte[] message) : base (3)
		{
			Decode (message);
		}
        
		/// <summary>
		/// Domain name
		/// </summary>
        public string Domain
        {
            get;
            private set;
        }
        
        /// <summary>
        /// Username
        /// </summary>
		public string Username 
        {
            get;
            private set;
		}

		// methods
		protected override void Decode (byte[] message)
		{
			base.Decode (message);

			if (BitConverterLE.ToUInt16 (message, 56) != message.Length) 
            {
				string msg = "Invalid Type3 message length.";
				throw new ArgumentException (msg, "message");
			}

            if (message.Length >= 64)
            {
                Flags = (Common.NtlmFlags)BitConverterLE.ToUInt32(message, 60);
            }
            else
            {
                Flags = (Common.NtlmFlags)0x8201;
            }
		
			int dom_len = BitConverterLE.ToUInt16 (message, 28);
			int dom_off = BitConverterLE.ToUInt16 (message, 32);
			this.Domain = DecodeString (message, dom_off, dom_len);

			int user_len = BitConverterLE.ToUInt16 (message, 36);
			int user_off = BitConverterLE.ToUInt16 (message, 40);
			this.Username = DecodeString (message, user_off, user_len);
		}

		string DecodeString (byte[] buffer, int offset, int len)
		{
            if ((Flags & Common.NtlmFlags.NegotiateUnicode) != 0)
            {
                return Encoding.Unicode.GetString(buffer, offset, len);
            }
            else
            {
                return Encoding.ASCII.GetString(buffer, offset, len);
            }
		}
	}
}
