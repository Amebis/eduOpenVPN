/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN Management console error
    /// </summary>
    [Serializable]
    public class CommandException : Exception
    {
        #region Constructors

        public CommandException(string message) :
            base(message)
        {
        }

        #endregion
    }
}
