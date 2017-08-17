/*
    eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.Threading;
using System.Threading.Tasks;

namespace System.IO
{
    public static class Extensions
    {
        /// <summary>
        /// Writes array of bytes to the <c>Stream</c>
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        public static void Write(this Stream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        public static async void WriteAsync(this Stream stream, byte[] buffer)
        {
            await stream.WriteAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to write to the <c>Stream</c></param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <c>None</c>.</param>
        public static async void WriteAsync(this Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c>
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        public static int Read(this Stream stream, byte[] buffer)
        {
            return stream.Read(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        public static async Task<int> ReadAsync(this Stream stream, byte[] buffer)
        {
            return await stream.ReadAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>Stream</c> asynchronously
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="buffer">An array of type <c>Byte</c> that contains the data to read from the <c>Stream</c></param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <c>None</c>.</param>
        public static async Task<int> ReadAsync(this Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            return await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
        }

        /// <summary>
        /// Writes array of bytes to the <c>StreamWriter</c>
        /// </summary>
        /// <param name="writer">StreamWriter</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to write to the <c>StreamWriter</c></param>
        public static void Write(this StreamWriter writer, char[] buffer)
        {
            writer.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Writes array of bytes to the <c>StreamWriter</c> asynchronously
        /// </summary>
        /// <param name="writer">StreamWriter</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to write to the <c>StreamWriter</c></param>
        public static async void WriteAsync(this StreamWriter writer, char[] buffer)
        {
            await writer.WriteAsync(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>StreamReader</c>
        /// </summary>
        /// <param name="reader">StreamReader</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to read from the <c>StreamReader</c></param>
        public static int Read(this StreamReader reader, char[] buffer)
        {
            return reader.Read(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Reads array of bytes from the <c>StreamReader</c> asynchronously
        /// </summary>
        /// <param name="reader">StreamReader</param>
        /// <param name="buffer">An array of type <c>char</c> that contains the data to read from the <c>StreamReader</c></param>
        public static async Task<int> ReadAsync(this StreamReader reader, char[] buffer)
        {
            return await reader.ReadAsync(buffer, 0, buffer.Length);
        }
    }
}
