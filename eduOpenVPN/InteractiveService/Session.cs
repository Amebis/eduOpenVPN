/*
eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;

namespace eduOpenVPN.InteractiveService
{
    /// <summary>
    /// OpenVPN Interactive Service connection
    /// </summary>
    public class Session : IDisposable
    {
        #region Properties

        /// <summary>
        /// Named pipe stream to OpenVPN Interactive Service
        /// </summary>
        public NamedPipeClientStream Stream { get => _stream; }
        private NamedPipeClientStream _stream;

        #endregion

        #region Constructors

        /// <summary>
        /// Construct an OpenVPN Interactive Service connection
        /// </summary>
        public Session()
        {
            _stream = new NamedPipeClientStream(".", "openvpn\\service");
        }

        #endregion

        #region Methods

        public void Connect(int timeout = 3000)
        {
            try
            {
                // Connect to OpenVPN Interactive Service via named pipe.
                _stream.Connect(timeout);
                _stream.ReadMode = PipeTransmissionMode.Message;
                if (_stream.CanTimeout)
                {
                    _stream.ReadTimeout = timeout;
                    _stream.WriteTimeout = timeout;
                }
            }
            catch (Exception ex) { throw new AggregateException(Resources.Strings.ErrorInteractiveServiceConnect, ex); }
        }

        /// <summary>
        /// Sends OpenVPN Interactive Service a command to start openvpn.exe
        /// </summary>
        /// <param name="working_folder">openvpn.exe process working folder to start in</param>
        /// <param name="arguments">openvpn.exe command line parameters</param>
        /// <param name="stdin">Text to send to openvpn.exe on start via stdin</param>
        /// <returns>openvpn.exe process ID</returns>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "MemoryStream tolerates multiple disposes.")]
        public uint RunOpenVPN(string working_folder, string[] arguments, string stdin)
        {
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

                _stream.Write(msg_stream.GetBuffer(), 0, (int)msg_stream.Length);
            }

            // Parse the response.
            var data = new byte[1048576]; // Limit to 1MiB
            var msg = new string(Encoding.Unicode.GetChars(data, 0, _stream.Read(data, 0, data.Length))).Replace("\r\n", "\n").Split('\n');
            var conv = new UInt32Converter();
            var error = (uint)conv.ConvertFromString(msg[0]);
            if (error == 0)
                return msg[2] == "Process ID" ? (uint)conv.ConvertFromString(msg[1]) : 0;
            else
                throw new InteractiveServiceException(error, msg[1], msg[2] != "(null)" ? msg[2] : null);
        }

        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                    _stream.Dispose();

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
