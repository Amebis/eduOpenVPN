/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduOpenVPN;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace System
{
    /// <summary>
    /// <see cref="System"/> namespace extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Returns the copy of sub-array
        /// </summary>
        /// <typeparam name="T">Array element type</typeparam>
        /// <param name="data">The Array</param>
        /// <param name="index">Starting index</param>
        /// <returns>Sub-array</returns>
        [DebuggerStepThrough]
        public static T[] SubArray<T>(this T[] data, long index)
        {
            T[] result = new T[data.LongLength - index];
            Array.Copy(data, index, result, 0, result.LongLength);
            return result;
        }

        /// <summary>
        /// Returns the copy of sub-array
        /// </summary>
        /// <typeparam name="T">Array element type</typeparam>
        /// <param name="data">The Array</param>
        /// <param name="index">Starting index</param>
        /// <param name="length">Number of elements to copy</param>
        /// <returns>Sub-array</returns>
        [DebuggerStepThrough]
        public static T[] SubArray<T>(this T[] data, long index, long length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

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

            string value_str = value.ToString();
            FieldInfo fieldInfo = value.GetType().GetField(value_str);
            var attribute = fieldInfo.GetCustomAttributes(typeof(ParameterValueAttribute), false).SingleOrDefault() as ParameterValueAttribute;
            return attribute != null ? attribute.Value : value_str;
        }
    }
}
