/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <c>RSASignRequested</c> event arguments
    /// </summary>
    public class RSASignRequestedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Data to be signed
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// PKCS#1 v1.5 signature of <c>Data</c> property
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
