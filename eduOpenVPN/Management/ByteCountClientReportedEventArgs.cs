/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2019 The Commons Conservancy eduVPN Programme
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
        /// <param name="bytes_in">Number of bytes that have been received from the server</param>
        /// <param name="bytes_out">Number of bytes that have been sent to the server</param>
        public ByteCountClientReportedEventArgs(uint cid, ulong bytes_in, ulong bytes_out) :
            base(bytes_in, bytes_out)
        {
            CID = cid;
        }

        #endregion
    }
}
