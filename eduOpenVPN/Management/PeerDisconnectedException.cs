/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Runtime.Serialization;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN Management session peer disconnected.
    /// </summary>
    [Serializable]
    public class PeerDisconnectedException : ApplicationException, ISerializable
    {
        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        public PeerDisconnectedException() :
            this(Resources.Strings.ErrorPeerDisconnected)
        { }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        public PeerDisconnectedException(string message) :
            base(message)
        {
        }

        #endregion
    }
}
