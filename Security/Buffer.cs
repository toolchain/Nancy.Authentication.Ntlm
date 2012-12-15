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
        public int BufferType;
        public IntPtr pvBuffer;

        public Buffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = (int)SecurityBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public Buffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)SecurityBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public Buffer(byte[] secBufferBytes, SecurityBufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
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
