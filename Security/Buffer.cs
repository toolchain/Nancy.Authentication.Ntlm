using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Nancy.Authentication.Ntlm.Security
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Buffer : IDisposable
    {
        public int cbBuffer;
        public int cbBufferType;
        public IntPtr pvBuffer;

        public Buffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            cbBufferType = (int)BufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public Buffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            cbBufferType = (int)BufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public Buffer(byte[] secBufferBytes, BufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            cbBufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }
}
