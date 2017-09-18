/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    public class ByteCountReportedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Number of bytes that have been received from the server
        /// </summary>
        public ulong BytesIn { get; }

        /// <summary>
        /// Number of bytes that have been sent to the server
        /// </summary>
        public ulong BytesOut { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="bytes_in">Number of bytes that have been received from the server</param>
        /// <param name="bytes_out">Number of bytes that have been sent to the server</param>
        public ByteCountReportedEventArgs(ulong bytes_in, ulong bytes_out)
        {
            BytesIn = bytes_in;
            BytesOut = bytes_out;
        }

        #endregion
    }
}
