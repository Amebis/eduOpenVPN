﻿/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2021 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Linq;
using System.Reflection;

namespace eduOpenVPN
{
    /// <summary>
    /// OpenVPN parameter string value (to apply to enum constants)
    /// </summary>
    public sealed class ParameterValueAttribute : Attribute
    {
        #region Properties

        /// <summary>
        /// Attribute value
        /// </summary>
        public string Value { get; private set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an attribute
        /// </summary>
        /// <param name="value">Value of the attribute</param>
        public ParameterValueAttribute(string value)
        {
            Value = value;
        }

        #endregion

        #region Methods

        /// <summary>
        /// Looks-up enum by <see cref="ParameterValueAttribute"/> value
        /// </summary>
        /// <typeparam name="T">Enum type</typeparam>
        /// <param name="value"><see cref="ParameterValueAttribute"/> value</param>
        /// <param name="result">Resulting enum</param>
        /// <returns><c>true</c> if enum found; <c>false</c> otherwise</returns>
        public static bool TryGetEnumByParameterValueAttribute<T>(string value, out T result)
        {
            Type enumType = typeof(T);
            foreach (T val in Enum.GetValues(enumType))
            {
                FieldInfo fi = enumType.GetField(val.ToString());
                if (fi.GetCustomAttributes(typeof(ParameterValueAttribute), false).SingleOrDefault() is ParameterValueAttribute attr && attr.Value == value)
                {
                    result = val;
                    return true;
                }
            }

            result = default;
            return false;
        }

        /// <summary>
        /// Looks-up enum by <see cref="ParameterValueAttribute"/> value
        /// </summary>
        /// <typeparam name="T">Enum type</typeparam>
        /// <param name="value"><see cref="ParameterValueAttribute"/> value</param>
        /// <returns>Resulting enum</returns>
        /// <exception cref="ArgumentException">No enum with <paramref name="value"/> as <see cref="ParameterValueAttribute"/> found</exception>
        public static T GetEnumByParameterValueAttribute<T>(string value)
        {
            if (TryGetEnumByParameterValueAttribute<T>(value, out var result))
                return result;

            throw new ArgumentException(string.Format(Resources.Strings.ErrorParameterValueNotFound, value, typeof(T).ToString()), nameof(value));
        }

        #endregion
    }
}
