/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Security;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <c>AuthenticationTokenReported</c> event arguments
    /// </summary>
    public class AuthenticationTokenReportedEventArgs : EventArgs, IDisposable
    {
        #region Properties

        /// <summary>
        /// Authentication token
        /// </summary>
        public SecureString Token { get => _token; }
        private SecureString _token;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="token">Authentication token</param>
        public AuthenticationTokenReportedEventArgs(SecureString token)
        {
            _token = token;
        }

        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_token != null)
                        _token.Dispose();
                }

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
