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

        public static T GetEnumByParameterValueAttribute<T>(string value)
        {
            Type enumType = typeof(T);
            foreach (T val in Enum.GetValues(enumType))
            {
                FieldInfo fi = enumType.GetField(val.ToString());
                if (fi.GetCustomAttributes(typeof(ParameterValueAttribute), false).SingleOrDefault() is ParameterValueAttribute attr && attr.Value == value)
                    return val;
            }

            throw new ArgumentException();
        }

        #endregion
    }
}
