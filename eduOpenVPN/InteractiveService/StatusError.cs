/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2018 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Diagnostics;

namespace eduOpenVPN.InteractiveService
{
    /// <summary>
    /// OpenVPN Interactive Service error message
    /// </summary>
    public class StatusError : Status
    {
        #region Properties

        /// <summary>
        /// OpenVPN Interactive Service function
        /// </summary>
        public string Function { get => _function; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private string _function;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an OpenVPN Interactive Service error message
        /// </summary>
        /// <param name="code">Status code (<c>0</c> success)</param>
        /// <param name="function">The function that failed</param>
        /// <param name="message">Additional error description (optional)</param>
        public StatusError(uint code, string function, string message) :
            base(code, message)
        {
            _function = function;
        }

        #endregion

        #region Methods

        /// <inheritdoc/>
        public override string ToString()
        {
            return String.Format("{0}: {1} (0x{2:X})", _function, Message, Code);
        }

        #endregion
    }
}
