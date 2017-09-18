/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Security.Cryptography.X509Certificates;

namespace eduOpenVPN.Management
{
    public class CertificateRequestedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// A hint about which certificate is required
        /// </summary>
        public string Hint { get; }

        /// <summary>
        /// Certificate
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="hint">A hint about which certificate is required</param>
        public CertificateRequestedEventArgs(string hint)
        {
            Hint = hint;
        }

        #endregion
    }
}
