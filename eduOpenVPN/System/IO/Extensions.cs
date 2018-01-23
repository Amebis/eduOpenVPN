/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace System.IO
{
    /// <summary>
    /// <c>System.IO</c> namespace extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Writes array of bytes to the <c>Stream</c>
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        [DebuggerStepThrough]
        public static void Write(this Stream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        [DebuggerStepThrough]
        public static Task WriteAsync(this Stream stream, byte[] buffer)
        {
            return stream.WriteAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <c>None</c>.</param>
        [DebuggerStepThrough]
        public static Task WriteAsync(this Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            return stream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c>
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        [DebuggerStepThrough]
        public static int Read(this Stream stream, byte[] buffer)
        {
            return stream.Read(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        [DebuggerStepThrough]
        public static Task<int> ReadAsync(this Stream stream, byte[] buffer)
        {
            return stream.ReadAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <c>None</c>.</param>
        [DebuggerStepThrough]
        public static Task<int> ReadAsync(this Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            return stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
        }

        /// <summary>
        /// Writes array of bytes to the <c>StreamWriter</c>
        /// </summary>
        /// <param name="writer">StreamWriter</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to write to the <c>StreamWriter</c></param>
        [DebuggerStepThrough]
        public static void Write(this StreamWriter writer, char[] buffer)
        {
            writer.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>StreamWriter</c> asynchronously
        /// </summary>
        /// <param name="writer">StreamWriter</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to write to the <c>StreamWriter</c></param>
        [DebuggerStepThrough]
        public static Task WriteAsync(this StreamWriter writer, char[] buffer)
        {
            return writer.WriteAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>StreamReader</c>
        /// </summary>
        /// <param name="reader">StreamReader</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to read from the <c>StreamReader</c></param>
        [DebuggerStepThrough]
        public static int Read(this StreamReader reader, char[] buffer)
        {
            return reader.Read(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>StreamReader</c> asynchronously
        /// </summary>
        /// <param name="reader">StreamReader</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to read from the <c>StreamReader</c></param>
        [DebuggerStepThrough]
        public static Task<int> ReadAsync(this StreamReader reader, char[] buffer)
        {
            return reader.ReadAsync(buffer, 0, buffer.Length);
        }
    }
}
