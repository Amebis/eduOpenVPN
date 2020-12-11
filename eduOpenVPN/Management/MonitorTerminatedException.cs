/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN Management monitor terminated error
    /// </summary>
    [Serializable]
    public class MonitorTerminatedException : AggregateException
    {
        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        public MonitorTerminatedException() :
            this(Resources.Strings.ErrorMonitorTerminated, null)
        { }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="innerException">Inner exception</param>
        public MonitorTerminatedException(Exception innerException) :
            this(Resources.Strings.ErrorMonitorTerminated, innerException)
        { }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public MonitorTerminatedException(string message, Exception innerException) :
            base(message, innerException)
        {
        }

        #endregion
    }
}
