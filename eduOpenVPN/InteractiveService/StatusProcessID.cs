/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.InteractiveService
{
    /// <summary>
    /// OpenVPN Interactive Service openvpn.exe process ID message
    /// </summary>
    public class StatusProcessID : Status
    {
        #region Properties

        /// <summary>
        /// openvpn.exe process ID
        /// </summary>
        public int ProcessID { get; private set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an OpenVPN Interactive Service openvpn.exe process ID message
        /// </summary>
        /// <param name="pid">openvpn.exe process ID</param>
        /// <param name="message">Additional error description (optional)</param>
        public StatusProcessID(int pid, string message) :
            base(0, message)
        {
            ProcessID = pid;
        }

        #endregion

        #region Methods

        /// <inheritdoc/>
        public override string ToString()
        {
            return String.Format("{0}: 0x{1:X}", Message, ProcessID);
        }

        #endregion
    }
}
