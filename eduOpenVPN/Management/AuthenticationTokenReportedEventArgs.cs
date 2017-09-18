/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    public class AuthenticationTokenReportedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Authentication token
        /// </summary>
        public byte[] Token { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="token">Authentication token</param>
        public AuthenticationTokenReportedEventArgs(byte[] token)
        {
            Token = token;
        }

        #endregion
    }
}
