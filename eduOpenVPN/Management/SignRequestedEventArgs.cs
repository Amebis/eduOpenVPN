﻿/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <see cref="Session.SignRequested"/> event arguments
    /// </summary>
    public class SignRequestedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Data to be signed
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Signing and padding algorithm
        /// </summary>
        public SignAlgorithmType Algorithm { get; }

        /// <summary>
        /// Signature of <see cref="Data"/> property
        /// </summary>
        public byte[] Signature { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="data">Data to be signed</param>
        /// <param name="algorithm">Signing and padding algorithm</param>
        public SignRequestedEventArgs(byte[] data, SignAlgorithmType algorithm)
        {
            Data = data;
            Algorithm = algorithm;
        }

        #endregion
    }
}