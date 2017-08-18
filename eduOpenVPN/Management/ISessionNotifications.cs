/*
    eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Net;

namespace eduOpenVPN.Management
{
    public interface ISessionNotifications
    {
        /// <summary>
        /// Called when BYTECOUNT real-time message is received
        /// </summary>
        /// <param name="bytes_in">Number of bytes that have been received from the server</param>
        /// <param name="bytes_out">Number of bytes that have been sent to the server</param>
        void OnByteCount(ulong bytes_in, ulong bytes_out);

        /// <summary>
        /// Called when BYTECOUNT_CLI real-time message is received
        /// </summary>
        /// <param name="cid">Client ID</param>
        /// <param name="bytes_in">Number of bytes that have been received from the client</param>
        /// <param name="bytes_out">Number of bytes that have been sent to the client</param>
        void OnByteCountClient(uint cid, ulong bytes_in, ulong bytes_out);

        /// <summary>
        /// Called when an echo command is received
        /// </summary>
        /// <param name="timestamp">Timestamp of the echo command</param>
        /// <param name="command">Echo command</param>
        void OnEcho(DateTimeOffset timestamp, string command);

        /// <summary>
        /// Called when OpenVPN reports fatal error
        /// </summary>
        /// <param name="message">Descriptive string</param>
        void OnFatal(string message);

        /// <summary>
        /// Called when OpenVPN is in a hold state
        /// </summary>
        /// <param name="message">Descriptive string</param>
        /// <param name="wait_hint">Indicates how long OpenVPN would wait without UI(as influenced by connect-retry exponential backoff). The UI needs to wait for releasing the hold if it wants similar behavior.</param>
        void OnHold(string message, int wait_hint);

        /// <summary>
        /// Called when a log entry is received
        /// </summary>
        /// <param name="timestamp">Timestamp of the log entry</param>
        /// <param name="flags">Log message flags</param>
        /// <param name="message">Log message</param>
        void OnLog(DateTimeOffset timestamp, LogMessageFlags flags, string message);

        /// <summary>
        /// Called when password is needed
        /// </summary>
        /// <param name="realm">Realm title</param>
        /// <param name="password">Password</param>
        void OnNeedAuthentication(string realm, out string password);

        /// <summary>
        /// Called when username and password is needed
        /// </summary>
        /// <param name="realm">Realm title</param>
        /// <param name="username">User name</param>
        /// <param name="password">Password</param>
        void OnNeedAuthentication(string realm, out string username, out string password);

        /// <summary>
        /// Called when authentication failed
        /// </summary>
        /// <param name="realm">Realm title</param>
        void OnAuthenticationFailed(string realm);

        /// <summary>
        /// Called when OpenVPN's initial state is reported
        /// </summary>
        /// <param name="timestamp">Timestamp of the state</param>
        /// <param name="message">Descriptive string (optional)</param>
        /// <param name="tunnel">TUN/TAP local IPv4 address (optional)</param>
        /// <param name="ipv6_tunnel">TUN/TAP local IPv6 address (optional)</param>
        /// <param name="remote">Remote server address and port (optional)</param>
        /// <param name="local">Local address and port (optional)</param>
        /// <remarks></remarks>
        void OnState(DateTimeOffset timestamp, OpenVPNStateType state, string message, IPAddress tunnel, IPAddress ipv6_tunnel, IPEndPoint remote, IPEndPoint local);
    }
}
