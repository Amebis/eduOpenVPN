/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN
{
    public enum ProtoType
    {
        /// <summary>
        /// UDP
        /// </summary>
        [ParameterValue("udp")]
        UDP = 0,

        /// <summary>
        /// TCP client
        /// </summary>
        [ParameterValue("tcp-client")]
        TCPClient,

        /// <summary>
        /// TCP server
        /// </summary>
        [ParameterValue("tcp-server")]
        TCPServer,
    }
}
