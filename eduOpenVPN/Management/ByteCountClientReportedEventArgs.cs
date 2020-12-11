/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <see cref="Session.ByteCountClientReported"/> event arguments
    /// </summary>
    public class ByteCountClientReportedEventArgs : ByteCountReportedEventArgs
    {
        #region Properties

        /// <summary>
        /// Client ID
        /// </summary>
        public uint CID { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="cid">Client ID</param>
        /// <param name="bytesIn">Number of bytes that have been received from the server</param>
        /// <param name="bytesOut">Number of bytes that have been sent to the server</param>
        public ByteCountClientReportedEventArgs(uint cid, ulong bytesIn, ulong bytesOut) :
            base(bytesIn, bytesOut)
        {
            CID = cid;
        }

        #endregion
    }
}
