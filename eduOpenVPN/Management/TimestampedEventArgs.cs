/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// Timestamped event arguments base class
    /// </summary>
    public class TimestampedEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// Timestamp of the event
        /// </summary>
        public DateTimeOffset TimeStamp { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="timestamp">Timestamp of the event</param>
        public TimestampedEventArgs(DateTimeOffset timestamp)
        {
            TimeStamp = timestamp;
        }

        #endregion
    }
}
