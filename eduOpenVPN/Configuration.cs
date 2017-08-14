/*
eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN
{
    public class Configuration
    {

        public static string EscapeParamValue(string value)
        {
            return value.IndexOfAny(new char[] { '\\', ' ', '"' }) >= 0 ?
                "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"" : // Escape backslash and double quotes, and add surrounding quotes
                value; // No need to escape
        }
    }
}
