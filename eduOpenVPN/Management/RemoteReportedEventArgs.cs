/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2018 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <see cref="Session.RemoteReported"/> event arguments
    /// </summary>
    public class RemoteReportedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Hostname or IP address
        /// </summary>
        public string Host { get; }

        /// <summary>
        /// IP Port
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// Protocol
        /// </summary>
        public ProtoType Protocol { get; }

        /// <summary>
        /// Required action for the given remote
        /// </summary>
        public RemoteAction Action { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="host">Hostname or IP address</param>
        /// <param name="port">IP Port</param>
        /// <param name="protocol">Protocol</param>
        public RemoteReportedEventArgs(string host, int port, ProtoType protocol)
        {
            Host = host;
            Port = port;
            Protocol = protocol;

            // Default action is accept.
            Action = new RemoteAcceptAction();
        }

        #endregion
    }
}
