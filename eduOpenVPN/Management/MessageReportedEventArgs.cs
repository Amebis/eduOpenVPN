/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    public class MessageReportedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Descriptive string
        /// </summary>
        public string Message { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="message">Descriptive string</param>
        public MessageReportedEventArgs(string message)
        {
            Message = message;
        }

        #endregion
    }
}
