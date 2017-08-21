/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN
{
    /// <summary>
    /// OpenVPN state type
    /// </summary>
    public enum OpenVPNStateType
    {
        /// <summary>
        /// Unknown state (default)
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// OpenVPN's initial state
        /// </summary>
        [ParameterValue("CONNECTING")]
        Connecting,

        /// <summary>
        /// Waiting for initial response from server (Client only)
        /// </summary>
        [ParameterValue("WAIT")]
        Waiting,

        /// <summary>
        /// Authenticating with server (Client only)
        /// </summary>
        [ParameterValue("AUTH")]
        Authenticating,

        /// <summary>
        /// Downloading configuration options from server (Client only)
        /// </summary>
        [ParameterValue("GET_CONFIG")]
        GettingConfiguration,

        /// <summary>
        /// Assigning IP address to virtual network interface
        /// </summary>
        [ParameterValue("ASSIGN_IP")]
        AssigningIP,

        /// <summary>
        /// Adding routes to system
        /// </summary>
        [ParameterValue("ADD_ROUTES")]
        AddingRoutes,

        /// <summary>
        /// Initialization Sequence Completed
        /// </summary>
        [ParameterValue("CONNECTED")]
        Connected,

        /// <summary>
        /// A restart has occurred
        /// </summary>
        [ParameterValue("RECONNECTING")]
        Reconnecting,

        /// <summary>
        /// A graceful exit is in progress
        /// </summary>
        [ParameterValue("EXITING")]
        Exiting,

        /// <summary>
        /// OpenVPN reported fatal error
        /// </summary>
        FatalError,
    }
}
