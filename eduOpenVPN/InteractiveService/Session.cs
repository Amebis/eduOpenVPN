/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace eduOpenVPN.InteractiveService
{
    /// <summary>
    /// OpenVPN Interactive Service session
    /// </summary>
    public class Session : IDisposable
    {
        #region Properties

        /// <summary>
        /// Named pipe stream to OpenVPN Interactive Service
        /// </summary>
        public NamedPipeClientStream Stream { get => _stream; }
        private NamedPipeClientStream _stream;

        /// <summary>
        /// openvpn.exe process ID
        /// </summary>
        public int ProcessID { get => _process_id; }
        private int _process_id;

        #endregion

        #region Methods

        /// <summary>
        /// Connects to OpenVPN Interactive Service and sends a command to start openvpn.exe
        /// </summary>
        /// <param name="pipe_name">Pipe name to connect to (e.g. "openvpn\\service")</param>
        /// <param name="working_folder">openvpn.exe process working folder to start in</param>
        /// <param name="arguments">openvpn.exe command line parameters</param>
        /// <param name="stdin">Text to send to openvpn.exe on start via stdin</param>
        /// <param name="timeout">The number of milliseconds to wait for the server to respond before the connection times out.</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>openvpn.exe process ID</returns>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "MemoryStream tolerates multiple disposes.")]
        public void Connect(string pipe_name, string working_folder, string[] arguments, string stdin, int timeout = 3000, CancellationToken ct = default(CancellationToken))
        {
            try
            {
                // Connect to OpenVPN Interactive Service via named pipe.
                _stream = new NamedPipeClientStream(".", pipe_name);
                _stream.Connect(timeout);
                _stream.ReadMode = PipeTransmissionMode.Message;
            }
            catch (Exception ex) { throw new AggregateException(String.Format(Resources.Strings.ErrorInteractiveServiceConnect, pipe_name), ex); }

            // Ask OpenVPN Interactive Service to start openvpn.exe for us.
            var encoding_utf16 = new UnicodeEncoding(false, false);
            using (var msg_stream = new MemoryStream())
            using (var writer = new BinaryWriter(msg_stream, encoding_utf16))
            {
                // Working folder (zero terminated)
                writer.Write(working_folder.ToArray());
                writer.Write((char)0);

                // openvpn.exe command line parameters (zero terminated)
                writer.Write(String.Join(" ", arguments.Select(arg => arg.IndexOfAny(new char[] { ' ', '"' }) >= 0 ? "\"" + arg.Replace("\"", "\\\"") + "\"" : arg)).ToArray());
                writer.Write((char)0);

                // stdin (zero terminated)
                writer.Write(stdin.ToArray());
                writer.Write((char)0);

                try { _stream.WriteAsync(msg_stream.GetBuffer(), 0, (int)msg_stream.Length).Wait(ct); }
                catch (OperationCanceledException) { throw; }
                catch (AggregateException ex) { throw ex.InnerException; }
            }

            // Read and analyse status.
            var status_task = ReadStatusAsync();
            try { status_task.Wait(ct); }
            catch (OperationCanceledException) { throw; }
            catch (AggregateException ex) { throw ex.InnerException; }
            if (status_task.Result is StatusError status_err && status_err.Code != 0)
                throw new InteractiveServiceException(status_err.Code, status_err.Function, status_err.Message);
            else if (status_task.Result is StatusProcessID status_pid)
                _process_id = status_pid.ProcessID;
            else
                _process_id = 0;
        }

        /// <summary>
        /// Disconnects from OpenVPN Interactive Service
        /// </summary>
        /// <remarks>Instead of calling this method, ensure that the connection is properly disposed.</remarks>
        public void Disconnect()
        {
            if (_stream != null)
            {
                _stream.Close();
                _stream = null;
            }
        }

        /// <summary>
        /// Reads OpenVPN Interactive reported status
        /// </summary>
        /// <returns>Status</returns>
        public async Task<Status> ReadStatusAsync()
        {
            var data = new byte[1048576]; // Limit to 1MiB
            return Status.FromResponse(new string(Encoding.Unicode.GetChars(data, 0, await _stream.ReadAsync(data, 0, data.Length))));
        }

        #endregion

        #region IDisposable Support
        /// <summary>
        /// Flag to detect redundant <see cref="Dispose(bool)"/> calls.
        /// </summary>
        private bool disposedValue = false;

        /// <summary>
        /// Called to dispose the object.
        /// </summary>
        /// <param name="disposing">Dispose managed objects</param>
        /// <remarks>
        /// To release resources for inherited classes, override this method.
        /// Call <c>base.Dispose(disposing)</c> within it to release parent class resources, and release child class resources if <paramref name="disposing"/> parameter is <c>true</c>.
        /// This method can get called multiple times for the same object instance. When the child specific resources should be released only once, introduce a flag to detect redundant calls.
        /// </remarks>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_stream != null)
                        _stream.Dispose();
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting resources.
        /// </summary>
        /// <remarks>
        /// This method calls <see cref="Dispose(bool)"/> with <c>disposing</c> parameter set to <c>true</c>.
        /// To implement resource releasing override the <see cref="Dispose(bool)"/> method.
        /// </remarks>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
