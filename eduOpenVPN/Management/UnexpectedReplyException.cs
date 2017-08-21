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
    /// The OpenVPN Management reply was not expected.
    /// </summary>
    [Serializable]
    public class UnexpectedReplyException : ProtocolException, ISerializable
    {
        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        public UnexpectedReplyException(string response, int start = 0) :
            this(Resources.Strings.ErrorUnexpectedReply, response, start)
        { }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="response">OpenVPN Management response</param>
        /// <param name="start">Starting offset in <paramref name="response"/></param>
        public UnexpectedReplyException(string message, string response, int start = 0) :
            base(message, response, start)
        {
        }

        #endregion
    }
}
