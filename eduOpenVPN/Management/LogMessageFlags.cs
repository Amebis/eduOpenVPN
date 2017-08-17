/*
    eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN log message flags
    /// </summary>
    [Flags]
    public enum LogMessageFlags
    {
        Informational = (1 << 0), // 1
        FatalError = (1 << 1), // 2
        NonFatalError = (1 << 2), // 4
        Warning = (1 << 3), // 8
        Debug = (1 << 4), // 16
    }
}
