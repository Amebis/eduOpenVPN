/*
    eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.ComponentModel;

namespace eduOpenVPN.InteractiveService
{
    /// <summary>
    /// OpenVPN Interactive Service status message
    /// </summary>
    public class Status
    {
        #region Properties

        /// <summary>
        /// OpenVPN Interactive Service status code
        /// </summary>
        public uint Code { get => _code; }
        private uint _code;

        /// <summary>
        /// OpenVPN Interactive Service message (optional)
        /// </summary>
        public string Message { get => _message; }
        private string _message;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an OpenVPN Interactive Service status message
        /// </summary>
        /// <param name="code">Status code (<c>0</c> success)</param>
        /// <param name="message">Status description message</param>
        public Status(uint code, string message)
        {
            _code = code;
            _message = message;
        }

        #endregion

        #region Methods

        public override string ToString()
        {
            return string.Format(_message != null ? "{0} (0x{1,X})" : "(0x{1,X})", _message, _code);
        }

        /// <summary>
        /// Parses OpenVPN Interactive Service response
        /// </summary>
        /// <param name="response">OpenVPN Interactive Service response</param>
        /// <returns><c>Status</c> or one of its derived class representing status</returns>
        public static Status FromResponse(string response)
        {
            var msg = response.Replace("\r\n", "\n").Split('\n');
            var conv = new UInt32Converter();
            var code = (uint)conv.ConvertFromString(msg[0]);
            if (code == 0 && msg[2] == "Process ID")
                return new StatusProcessId((int)(uint)conv.ConvertFromString(msg[1]), msg[2]);
            else
                return new StatusError(code, msg[1], msg[2] != "(null)" ? msg[2] : null);
        }

        #endregion
    }
}
