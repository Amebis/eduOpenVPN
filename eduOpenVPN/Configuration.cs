/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;

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
            return EscapeParamValue(value, false);
        }

        /// <summary>
        /// Escapes value string to be used as a parameter in OpenVPN configuration file (.ovpn)
        /// </summary>
        /// <param name="value">Parameter value</param>
        /// <param name="force">Force quote</param>
        /// <returns>Quoted and escaped <paramref name="value"/> when escaping required; <paramref name="value"/> otherwise</returns>
        public static string EscapeParamValue(string value, bool force)
        {
            return value.Length > 0 ?
                force || value.IndexOfAny(new char[] { '\\', ' ', '"', '\'' }) >= 0 ?
                    "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"" : // Escape backslash and double quotes, and add surrounding quotes
                    value : // No need to escape
                    "\"\""; // Empty string
        }

        /// <summary>
        /// Parses OpenVPN command line
        /// </summary>
        /// <param name="command_line">Command line to parse</param>
        /// <returns>List of string parameters</returns>
        /// <exception cref="ArgumentException">Command line parsing failed</exception>
        /// <remarks>This method is OpenVPN v2.5 <c>parse_line()</c> function ported to C#.</remarks>
        public static List<string> ParseParams(string command_line)
        {
            List<string> ret = new List<string>();
            int offset = 0, offset_end = command_line.Length;
            ParseParamsState state = ParseParamsState.Initial;
            bool backslash = false;
            char char_in, char_out;
            string parm = "";

            do
            {
                char_in = offset < offset_end ? command_line[offset] : default(char);
                char_out = default(char);

                if (!backslash && char_in == '\\' && state != ParseParamsState.ReadingSingleQuotedParam)
                    backslash = true;
                else
                {
                    if (state == ParseParamsState.Initial)
                    {
                        if (!IsZeroOrWhiteChar(char_in))
                        {
                            if (char_in == ';' || char_in == '#') // comment
                                break;
                            if (!backslash && char_in == '\"')
                                state = ParseParamsState.ReadingQuotedParam;
                            else if (!backslash && char_in == '\'')
                                state = ParseParamsState.ReadingSingleQuotedParam;
                            else
                            {
                                char_out = char_in;
                                state = ParseParamsState.ReadingUnquotedParam;
                            }
                        }
                    }
                    else if (state == ParseParamsState.ReadingUnquotedParam)
                    {
                        if (!backslash && IsZeroOrWhiteChar(char_in))
                            state = ParseParamsState.Done;
                        else
                            char_out = char_in;
                    }
                    else if (state == ParseParamsState.ReadingQuotedParam)
                    {
                        if (!backslash && char_in == '\"')
                            state = ParseParamsState.Done;
                        else
                            char_out = char_in;
                    }
                    else if (state == ParseParamsState.ReadingSingleQuotedParam)
                    {
                        if (char_in == '\'')
                            state = ParseParamsState.Done;
                        else
                            char_out = char_in;
                    }

                    if (state == ParseParamsState.Done)
                    {
                        ret.Add(parm);
                        state = ParseParamsState.Initial;
                        parm = "";
                    }

                    if (backslash && char_out != default(char))
                    {
                        if (!(char_out == '\\' || char_out == '\"' || IsZeroOrWhiteChar(char_out)))
                            throw new ArgumentException(Resources.Strings.ErrorBadBackslash, "command_line");
                    }
                    backslash = false;
                }

                // Store parameter character.
                if (char_out != default(char))
                    parm += char_out;
            }
            while (offset++ < offset_end);

            switch (state)
            {
                case ParseParamsState.Initial: break;
                case ParseParamsState.ReadingQuotedParam: throw new ArgumentException(Resources.Strings.ErrorNoClosingQuotation, "command_line");
                case ParseParamsState.ReadingSingleQuotedParam: throw new ArgumentException(Resources.Strings.ErrorNoClosingSingleQuotation, "command_line");
                default: throw new ArgumentException(String.Format(Resources.Strings.ErrorResidualParseState, state), "command_line");
            }

            return ret;
        }

        /// <summary>
        /// <c>ParseParams</c> internal state
        /// </summary>
        private enum ParseParamsState
        {
            Initial = 0,
            ReadingQuotedParam,
            ReadingUnquotedParam,
            Done,
            ReadingSingleQuotedParam,
        };

        /// <summary>
        /// Indicates whether a Unicode character is zero or categorized as white space.
        /// </summary>
        /// <param name="c">The Unicode character to evaluate</param>
        /// <returns><c>true</c> if <paramref name="c"/> is zero or white space; <c>false</c>otherwise</returns>
        private static bool IsZeroOrWhiteChar(char c)
        {
            return c == default(char) || char.IsWhiteSpace(c);
        }
    }
}
