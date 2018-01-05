/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN session state error
    /// </summary>
    [Serializable]
    public class SessionStateException : ApplicationException
    {
        #region Constructors

        public SessionStateException(string message) :
            base(message)
        {
        }

        #endregion
    }
}
