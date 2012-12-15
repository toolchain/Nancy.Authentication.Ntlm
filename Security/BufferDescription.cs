using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Nancy.Authentication.Ntlm.Security
{
    [StructLayout(LayoutKind.Sequential)]
    public struct BufferDesciption : IDisposable
    {

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers; //Point to SecBuffer

        public BufferDesciption(int bufferSize)
        {
            ulVersion = (int)BufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            Buffer ThisSecBuffer = new Buffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public BufferDesciption(byte[] secBufferBytes)
        {
            ulVersion = (int)BufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            Buffer ThisSecBuffer = new Buffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public BufferDesciption(BufferHelper[] secBufferBytesArray)
        {
            if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
            {
                throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
            }

            ulVersion = (int)BufferType.SECBUFFER_VERSION;
            cBuffers = secBufferBytesArray.Length;

            //Allocate memory for SecBuffer Array....
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Buffer)) * cBuffers);

            for (int Index = 0; Index < secBufferBytesArray.Length; Index++)
            {
                //Super hack: Now allocate memory for the individual SecBuffers
                //and just copy the bit values to the SecBuffer array!!!
                Buffer ThisSecBuffer = new Buffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                //We will write out bits in the following order:
                //int cbBuffer;
                //int BufferType;
                //pvBuffer;
                //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                //are disposed...
                int CurrentOffset = Index * Marshal.SizeOf(typeof(Buffer));
                Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.cbBufferType);
                Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.cbBufferType), ThisSecBuffer.pvBuffer);
            }
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    Buffer ThisSecBuffer = (Buffer)Marshal.PtrToStructure(pBuffers, typeof(Buffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                        //SecBuffer and release it...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(Buffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                Buffer ThisSecBuffer = (Buffer)Marshal.PtrToStructure(pBuffers, typeof(Buffer));

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //What we need to do here calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(Buffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Now iterate over the individual buffers and put them together into a
                    //byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(Buffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }

        /*public SecBuffer GetSecBuffer()
        {
            if(pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            return((SecBuffer)Marshal.PtrToStructure(pBuffers,typeof(SecBuffer)));
        }*/
    }
}
