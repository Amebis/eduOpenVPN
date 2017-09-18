/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

namespace eduOpenVPN.Management
{
    public class UsernamePasswordAuthenticationRequestedEventArgs : PasswordAuthenticationRequestedEventArgs
    {
        #region Properties

        /// <summary>
        /// User name
        /// </summary>
        public string UserName { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="realm">Realm title</param>
        public UsernamePasswordAuthenticationRequestedEventArgs(string realm) :
            base(realm)
        {
        }

        #endregion
    }
}
