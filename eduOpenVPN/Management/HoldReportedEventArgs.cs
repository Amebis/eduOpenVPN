/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN.Management
{
    /// <summary>
    /// <see cref="Session.HoldReported"/> event arguments
    /// </summary>
    public class HoldReportedEventArgs : MessageReportedEventArgs
    {
        #region Properties

        /// <summary>
        /// Indicates how long OpenVPN would wait without UI(as influenced by connect-retry exponential backoff). The UI needs to wait for releasing the hold if it wants similar behavior.
        /// </summary>
        public int WaitHint { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="message">Descriptive string</param>
        /// <param name="wait_hint">Indicates how long OpenVPN would wait without UI(as influenced by connect-retry exponential backoff). The UI needs to wait for releasing the hold if it wants similar behavior.</param>
        public HoldReportedEventArgs(string message, int wait_hint) :
            base(message)
        {
            WaitHint = wait_hint;
        }

        #endregion
    }
}
