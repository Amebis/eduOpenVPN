/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <see cref="Session.RSASignRequested"/> event arguments
    /// </summary>
    public class RSASignRequestedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Data to be signed
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// PKCS#1 v1.5 signature of <see cref="Data"/> property
        /// </summary>
        public byte[] Signature { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="data">Data to be signed</param>
        public RSASignRequestedEventArgs(byte[] data)
        {
            Data = data;
        }

        #endregion
    }
}
