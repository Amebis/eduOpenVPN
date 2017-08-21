/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN
{
    /// <summary>
    /// Unix signals used by OpenVPN
    /// </summary>
    public enum SignalType
    {
        SIGHUP = 1,
        SIGTERM = 15,
        SIGUSR1,
        SIGUSR2,
    }
}
