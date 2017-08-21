/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN
{
    public class Configuration
    {
        /// <summary>
        /// Escapes value string to be used as a parameter in OpenVPN configuration file (.ovpn)
        /// </summary>
        /// <param name="value">Parameter value</param>
        /// <returns>Quoted and escaped <paramref name="value"/> when escaping required; <paramref name="value"/> otherwise</returns>
        public static string EscapeParamValue(string value)
        {
            return value.IndexOfAny(new char[] { '\\', ' ', '"', '\'' }) >= 0 ?
                "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"" : // Escape backslash and double quotes, and add surrounding quotes
                value; // No need to escape
        }
    }
}
