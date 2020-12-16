/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace eduOpenVPN
{
    public static class Extensions
    {
        /// <summary>
        /// Returns <see cref="ParameterValueAttribute"/> attribute value
        /// </summary>
        /// <param name="value">Enum</param>
        /// <returns>String with attribute value or stringized <paramref name="value"/></returns>
        [DebuggerStepThrough]
        public static string GetParameterValue(this Enum value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            string valueStr = value.ToString();
            FieldInfo fieldInfo = value.GetType().GetField(valueStr);
            return fieldInfo.GetCustomAttributes(typeof(ParameterValueAttribute), false).SingleOrDefault() is ParameterValueAttribute attribute ? attribute.Value : valueStr;
        }
    }
}
