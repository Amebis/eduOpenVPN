/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
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
    public class ParameterValueAttribute : Attribute
    {
        #region Properties

        /// <summary>
        /// Attribute value
        /// </summary>
        public string Value { get => _value; }
        private string _value;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an attribute
        /// </summary>
        /// <param name="value">Value of the attribute</param>
        public ParameterValueAttribute(string value)
        {
            _value = value;
        }

        #endregion

        #region Methods

        /// <summary>
        /// Looks-up enum by <c>ParameterValueAttribute</c> value
        /// </summary>
        /// <typeparam name="T">Enum type</typeparam>
        /// <param name="value"><c>ParameterValueAttribute</c> value</param>
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

            result = default(T);
            return false;
        }

        /// <summary>
        /// Looks-up enum by <c>ParameterValueAttribute</c> value
        /// </summary>
        /// <typeparam name="T">Enum type</typeparam>
        /// <param name="value"><c>ParameterValueAttribute</c> value</param>
        /// <returns>Resulting enum</returns>
        /// <exception cref="ArgumentException">No enum with <paramref name="value"/> as <c>ParameterValueAttribute</c> found</exception>
        public static T GetEnumByParameterValueAttribute<T>(string value)
        {
            if (TryGetEnumByParameterValueAttribute<T>(value, out var result))
                return result;

            throw new ArgumentException(String.Format(Resources.Strings.ErrorParameterValueNotFound, value, typeof(T).ToString()), "value");
        }

        #endregion
    }
}
