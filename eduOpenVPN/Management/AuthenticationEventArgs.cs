/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// Authentication events base class
    /// </summary>
    public class AuthenticationEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Realm title
        /// </summary>
        public string Realm { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="realm">Realm title</param>
        public AuthenticationEventArgs(string realm)
        {
            Realm = realm;
        }

        #endregion
    }
}
