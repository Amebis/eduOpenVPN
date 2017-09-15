﻿/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN Management session remote "SKIP" command action
    /// </summary>
    public class RemoteSkipAction : RemoteAction
    {
        #region Methods

        public override string ToString()
        {
            return "SKIP";
        }

        #endregion
    }
}