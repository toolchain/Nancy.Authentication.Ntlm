using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Nancy.Authentication.Ntlm.Security
{
    public struct MultipleSecBufferHelper
    {
        public byte[] Buffer;
        public BufferType BufferType;

        public MultipleSecBufferHelper(byte[] buffer, BufferType bufferType)
        {
            if (buffer == null || buffer.Length == 0)
            {
                throw new ArgumentException("buffer cannot be null or 0 length");
            }

            Buffer = buffer;
            BufferType = bufferType;
        }
    };
}
