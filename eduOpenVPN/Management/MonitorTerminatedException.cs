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
        /// <param name="inner_exception">Inner exception</param>
        public MonitorTerminatedException(Exception inner_exception) :
            this(Resources.Strings.ErrorMonitorTerminated, inner_exception)
        { }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="inner_exception">Inner exception</param>
        public MonitorTerminatedException(string message, Exception inner_exception) :
            base(message, inner_exception)
        {
        }

        #endregion
    }
}
