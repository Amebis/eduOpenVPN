/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduEx.Async;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace eduOpenVPN.Management
{
    /// <summary>
    /// OpenVPN Management console session
    /// </summary>
    public class Session : IDisposable
    {
        #region Data Types

        /// <summary>
        /// Command base class
        /// </summary>
        public class Command : IDisposable
        {
            /// <summary>
            /// Event to wait for command completition.
            /// </summary>
            public EventWaitHandle Finished = new EventWaitHandle(false, EventResetMode.ManualReset);

            #region IDisposable Support
            /// <summary>
            /// Flag to detect redundant <see cref="Dispose(bool)"/> calls.
            /// </summary>
            [DebuggerBrowsable(DebuggerBrowsableState.Never)]
            private bool disposedValue = false;

            /// <summary>
            /// Called to dispose the object.
            /// </summary>
            /// <param name="disposing">Dispose managed objects</param>
            /// <remarks>
            /// To release resources for inherited classes, override this method.
            /// Call <c>base.Dispose(disposing)</c> within it to release parent class resources, and release child class resources if <paramref name="disposing"/> parameter is <c>true</c>.
            /// This method can get called multiple times for the same object instance. When the child specific resources should be released only once, introduce a flag to detect redundant calls.
            /// </remarks>
            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                    {
                        if (Finished != null)
                            Finished.Dispose();
                    }

                    disposedValue = true;
                }
            }

            /// <summary>
            /// Performs application-defined tasks associated with freeing, releasing, or resetting resources.
            /// </summary>
            /// <remarks>
            /// This method calls <see cref="Dispose(bool)"/> with <c>disposing</c> parameter set to <c>true</c>.
            /// To implement resource releasing override the <see cref="Dispose(bool)"/> method.
            /// </remarks>
            public void Dispose()
            {
                // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                Dispose(true);
            }
            #endregion
        }

        /// <summary>
        /// Single command
        /// </summary>
        public class SingleCommand : Command
        {
            /// <summary>
            /// Did command finished successfully?
            /// </summary>
            public bool Success;

            /// <summary>
            /// Command response (or error message)
            /// </summary>
            public string Response;
        }

        /// <summary>
        /// Multiline command base class
        /// </summary>
        public class MultilineCommand : Command
        {
            /// <summary>
            /// Process one line of data returned from command
            /// </summary>
            /// <param name="data">Message data</param>
            /// <param name="session">OpenVPN management session</param>
            public virtual void ProcessData(string data, Session session)
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Commands combined of one single and one multiline command
        /// </summary>
        public class CombinedCommands
        {
            /// <summary>
            /// First command
            /// </summary>
            public SingleCommand first;

            /// <summary>
            /// Second command
            /// </summary>
            public MultilineCommand second;
        }

        /// <summary>
        /// "echo" command
        /// </summary>
        private class EchoCommand : MultilineCommand
        {
            /// <inheritdoc/>
            public override void ProcessData(string data, Session session)
            {
                var fields = data.Split(FieldSeparators, 2);
                session.EchoReceived?.Invoke(session, new EchoReceivedEventArgs(
                    long.TryParse(fields[0].Trim(), out var unixTime) ? Epoch.AddSeconds(unixTime) : DateTimeOffset.UtcNow,
                    fields.Length > 1 ? fields[1].Trim() : null));
            }
        }

        /// <summary>
        /// "hold" command
        /// </summary>
        private class HoldCommand : MultilineCommand
        {
            /// <inheritdoc/>
            public override void ProcessData(string data, Session session)
            {
                var fields = data.Split(MsgSeparators, 2 + 1);
                session.HoldReported?.Invoke(session, new HoldReportedEventArgs(
                    fields[0].Trim(),
                    fields.Length > 1 && int.TryParse(fields[1].Trim(), out var hint) ? hint : 0));
            }
        }

        /// <summary>
        /// "log" command
        /// </summary>
        private class LogCommand : MultilineCommand
        {
            /// <inheritdoc/>
            public override void ProcessData(string data, Session session)
            {
                var fields = data.Split(FieldSeparators, 2 + 1);
                session.LogReported?.Invoke(session, new LogReportedEventArgs(
                    long.TryParse(fields[0].Trim(), out var unixTime) ? Epoch.AddSeconds(unixTime) : DateTimeOffset.UtcNow,
                    fields.Length > 1 ?
                        (fields[1].IndexOf('I') >= 0 ? LogMessageFlags.Informational : 0) |
                        (fields[1].IndexOf('F') >= 0 ? LogMessageFlags.FatalError : 0) |
                        (fields[1].IndexOf('N') >= 0 ? LogMessageFlags.NonFatalError : 0) |
                        (fields[1].IndexOf('W') >= 0 ? LogMessageFlags.Warning : 0) |
                        (fields[1].IndexOf('D') >= 0 ? LogMessageFlags.Debug : 0)
                        : 0,
                    fields.Length > 2 ? fields[2].Trim() : null));
            }
        }

        /// <summary>
        /// "state" command
        /// </summary>
        private class StateCommand : MultilineCommand
        {
            /// <inheritdoc/>
            public override void ProcessData(string data, Session session)
            {
                var fields = data.Split(FieldSeparators, 9 + 1);
                session.StateReported?.Invoke(session, new StateReportedEventArgs(
                    long.TryParse(fields[0].Trim(), out var unixTime) ? Epoch.AddSeconds(unixTime) : DateTimeOffset.UtcNow,
                    fields.Length > 1 && ParameterValueAttribute.TryGetEnumByParameterValueAttribute<OpenVPNStateType>(fields[1].Trim(), out var state) ? state : default,
                    fields.Length > 2 ? fields[2].Trim() : null,
                    fields.Length > 3 && IPAddress.TryParse(fields[3].Trim(), out var address) ? address : null,
                    fields.Length > 8 && IPAddress.TryParse(fields[8].Trim(), out var ipv6Address) ? ipv6Address : null,
                    fields.Length > 5 && IPAddress.TryParse(fields[4].Trim(), out var remoteAddress) && int.TryParse(fields[5].Trim(), out var remotePort) ? new IPEndPoint(remoteAddress, remotePort) : null,
                    fields.Length > 7 && IPAddress.TryParse(fields[6].Trim(), out var localAddress) && int.TryParse(fields[7].Trim(), out var localPort) ? new IPEndPoint(localAddress, localPort) : null));
            }
        }

        /// <summary>
        /// "version" command
        /// </summary>
        private class VersionCommand : MultilineCommand
        {
            /// <summary>
            /// OpenVPN version
            /// </summary>
            public Dictionary<string, string> Version { get; } = new Dictionary<string, string>();

            /// <inheritdoc/>
            public override void ProcessData(string data, Session session)
            {
                var fields = data.Split(MsgSeparators, 1 + 1);
                if (fields.Length > 0)
                    Version[fields[0]] = fields.Length > 1 ? fields[1].Trim() : null;
            }
        }

        #endregion

        #region Fields

        /// <summary>
        /// Used to convert Unix timestamps into <see cref="DateTimeOffset"/>
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly DateTimeOffset Epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, new TimeSpan(0, 0, 0));

        /// <summary>
        /// Message separators
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly char[] MsgSeparators = new char[] { ':' };

        /// <summary>
        /// Field separators
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly char[] FieldSeparators = new char[] { ',' };

        /// <summary>
        /// Queue of pending commands
        /// </summary>
        private Queue<Command> Commands;

        /// <summary>
        /// Lock to serialize command submission
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private object CommandsLock;

        /// <summary>
        /// Waitable event to signal the monitor finished
        /// </summary>
        private EventWaitHandle MonitorFinished = new EventWaitHandle(false, EventResetMode.ManualReset);

        /// <summary>
        /// Cached credentials
        /// </summary>
        private NetworkCredential Credentials;

        #endregion

        #region Properties

        /// <summary>
        /// Network stream to OpenVPN Management console
        /// </summary>
        public NetworkStream Stream { get => _Stream; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private NetworkStream _Stream;

        /// <summary>
        /// Session monitor
        /// </summary>
        public Thread Monitor { get => _Monitor; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Thread _Monitor;

        /// <summary>
        /// Session monitor error
        /// </summary>
        public Exception Error { get => _Error; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Exception _Error;

        /// <summary>
        /// Raised when BYTECOUNT real-time message is received
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<ByteCountReportedEventArgs> ByteCountReported;

        /// <summary>
        /// Raised when BYTECOUNT_CLI real-time message is received
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<ByteCountClientReportedEventArgs> ByteCountClientReported;

        /// <summary>
        /// Raised when an echo command is received
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<EchoReceivedEventArgs> EchoReceived;

        /// <summary>
        /// Raised when OpenVPN reports fatal error
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<MessageReportedEventArgs> FatalErrorReported;

        /// <summary>
        /// Raised when OpenVPN is in a hold state
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<HoldReportedEventArgs> HoldReported;

        /// <summary>
        /// Raised when OpenVPN reports informative message
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<MessageReportedEventArgs> InfoReported;

        /// <summary>
        /// Raised when a log entry is received
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<LogReportedEventArgs> LogReported;

        /// <summary>
        /// Raised when openvpn.exe requires a certificate
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<CertificateRequestedEventArgs> CertificateRequested;

        /// <summary>
        /// Raised when password is needed
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<PasswordAuthenticationRequestedEventArgs> PasswordAuthenticationRequested;

        /// <summary>
        /// Raised when username and password is needed
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<UsernamePasswordAuthenticationRequestedEventArgs> UsernamePasswordAuthenticationRequested;

        /// <summary>
        /// Raised when authentication failed
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<AuthenticationEventArgs> AuthenticationFailed;

        /// <summary>
        /// Raised when authentication token received
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<AuthenticationTokenReportedEventArgs> AuthenticationTokenReported;

        /// <summary>
        /// Raised when remote endpoint is needed
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<RemoteReportedEventArgs> RemoteReported;

        /// <summary>
        /// Raised when RSA data signing is required
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<SignRequestedEventArgs> SignRequested;

        /// <summary>
        /// Raised when OpenVPN's initial state is reported
        /// </summary>
        /// <remarks>Sender is the OpenVPN management session <see cref="eduOpenVPN.Management.Session"/>.</remarks>
        public event EventHandler<StateReportedEventArgs> StateReported;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs a session
        /// </summary>
        public Session()
        {
            EchoReceived += (object sender, EchoReceivedEventArgs e) =>
            {
                if (e.Command == "forget-passwords")
                {
                    // Reset cached credentials.
                    Credentials = null;
                }
            };

            AuthenticationFailed += (object sender, AuthenticationEventArgs e) =>
            {
                // Reset cached credentials to force user re-prompting.
                Credentials = null;
            };

            AuthenticationTokenReported += (object sender, AuthenticationTokenReportedEventArgs e) =>
            {
                if (Credentials != null)
                {
                    // Save authentication token. OpenVPN accepts it as the password on reauthentications.
                    Credentials.SecurePassword = e.Token;
                }
            };
        }

        #endregion

        #region Methods

        /// <summary>
        /// Starts an OpenVPN Management console session
        /// </summary>
        /// <param name="stream"><see cref="NetworkStream"/> of already established connection</param>
        /// <param name="password">OpenVPN Management interface password</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="UnexpectedReplyException">OpenVPN Management did not start conversation with <c>&quot;ENTER PASSWORD:&quot;</c>.</exception>
        /// <exception cref="CommandException">Authentication using <paramref name="password"/> failed.</exception>
        public void Start(NetworkStream stream, string password, CancellationToken ct = default)
        {
            _Stream = stream;
            var reader = new StreamReader(_Stream, Encoding.UTF8, false);
            var serviceReady = new EventWaitHandle(false, EventResetMode.ManualReset);

            if (password != null)
            {
                // Read the password prompt.
                var buffer = new char[15];
                reader.ReadBlock(buffer, 0, buffer.Length, ct);
                if (buffer.Length < 15 || new String(buffer) != "ENTER PASSWORD:")
                    throw new UnexpectedReplyException(new String(buffer));
            }

            Commands = new Queue<Command>();
            CommandsLock = new object();

            // Spawn the monitor.
            _Monitor = new Thread(new ThreadStart(
                () =>
                {
                    try
                    {
                        for (;;)
                        {
                            ct.ThrowIfCancellationRequested();

                            // Read one line.
                            var line = reader.ReadLine(ct);

                            ct.ThrowIfCancellationRequested();

                            if (line == null)
                            {
                                // The OpenVPN Management Interface closed the connection after reporting ">FATAL".
                                // Keep the thread for client to display error and to allow user to examine OpenVPN log.
                                ct.WaitHandle.WaitOne();
                                throw new OperationCanceledException();
                            }

                            if (line.Length > 0 && line[0] == '>')
                            {
                                // Real-time notification message.
                                var msg = line.Substring(1).Split(MsgSeparators, 2);
                                switch (msg[0].Trim())
                                {
                                    case "BYTECOUNT":
                                        {
                                            var fields = msg[1].Split(FieldSeparators, 2 + 1);
                                            ByteCountReported?.Invoke(this, new ByteCountReportedEventArgs(
                                                fields.Length > 0 && ulong.TryParse(fields[0].Trim(), out var bytesIn) ? bytesIn : 0,
                                                fields.Length > 1 && ulong.TryParse(fields[1].Trim(), out var bytesOut) ? bytesOut : 0
                                            ));
                                        }
                                        break;

                                    case "BYTECOUNT_CLI":
                                        {
                                            var fields = msg[1].Split(FieldSeparators, 3 + 1);
                                            ByteCountClientReported?.Invoke(this, new ByteCountClientReportedEventArgs(
                                                fields.Length > 0 && uint.TryParse(fields[0].Trim(), out var cid) ? cid : 0,
                                                fields.Length > 1 && ulong.TryParse(fields[1].Trim(), out var bytesIn) ? bytesIn : 0,
                                                fields.Length > 2 && ulong.TryParse(fields[2].Trim(), out var bytesOut) ? bytesOut : 0
                                            ));
                                        }
                                        break;

                                    case "CLIENT":
                                        // TODO: Implement.
                                        break;

                                    case "CRV1":
                                        // TODO: Implement.
                                        break;

                                    case "ECHO":
                                        new EchoCommand().ProcessData(msg[1], this);
                                        break;

                                    case "FATAL":
                                        FatalErrorReported?.Invoke(this, new MessageReportedEventArgs(msg[1]));
                                        break;

                                    case "HOLD":
                                        new HoldCommand().ProcessData(msg[1], this);
                                        break;

                                    case "INFO":
                                        // Interactive service is ready only after it reports ">INFO".
                                        serviceReady.Set();
                                        InfoReported?.Invoke(this, new MessageReportedEventArgs(msg[1]));
                                        break;

                                    case "LOG":
                                        new LogCommand().ProcessData(msg[1], this);
                                        break;

                                    case "NEED-OK":
                                        // TODO: Implement.
                                        break;

                                    case "NEED-CERTIFICATE":
                                        {
                                            // Get certificate.
                                            var e = new CertificateRequestedEventArgs(msg[1]);
                                            CertificateRequested?.Invoke(this, e);

                                            // Reply with certificate command.
                                            var sb = new StringBuilder();
                                            sb.Append("certificate\n-----BEGIN CERTIFICATE-----\n");
                                            sb.Append(Convert.ToBase64String(e.Certificate.GetRawCertData(), Base64FormattingOptions.InsertLineBreaks).Replace("\r", ""));
                                            sb.Append("\n-----END CERTIFICATE-----\nEND");
                                            SendCommand(sb.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "NEED-STR":
                                        // TODO: Implement.
                                        break;

                                    case "PASSWORD":
                                        {
                                            if (msg[1].StartsWith("Verification Failed: "))
                                                AuthenticationFailed?.Invoke(this, new AuthenticationEventArgs(msg[1].Substring(21).Trim(new char[] { '\'' })));
                                            else if (msg[1].StartsWith("Auth-Token:"))
                                                AuthenticationTokenReported?.Invoke(this, new AuthenticationTokenReportedEventArgs(new NetworkCredential("", msg[1].Substring(11)).SecurePassword));
                                            else
                                            {
                                                var param = Configuration.ParseParams(msg[1]);
                                                if (param.Count > 2 && param[0] == "Need")
                                                {
                                                    switch (param[2])
                                                    {
                                                        case "password":
                                                            {
                                                                var e = new PasswordAuthenticationRequestedEventArgs(param[1]);
                                                                PasswordAuthenticationRequested?.Invoke(this, e);
                                                                if (e.Password == null)
                                                                    throw new OperationCanceledException();

                                                                // Send reply message.
                                                                SendCommand("password " + Configuration.EscapeParamValue(param[1]) + " " + Configuration.EscapeParamValue(new NetworkCredential("", e.Password).Password), new SingleCommand(), ct);
                                                            }
                                                            break;

                                                        case "username/password":
                                                            {
                                                                if (Credentials == null)
                                                                {
                                                                    // TODO: Support Static challenge/response protocol (PASSWORD:Need 'Auth' username/password SC:<ECHO>,<TEXT>)

                                                                    var e = new UsernamePasswordAuthenticationRequestedEventArgs(param[1]);
                                                                    UsernamePasswordAuthenticationRequested?.Invoke(this, e);
                                                                    if (e.Username == null || e.Password == null)
                                                                        throw new OperationCanceledException();

                                                                    // Prepare new credentials.
                                                                    Credentials = new NetworkCredential(e.Username, "") { SecurePassword = e.Password };
                                                                }

                                                                // Send reply messages.
                                                                var realmEsc = Configuration.EscapeParamValue(param[1]);
                                                                SendCommand("username " + realmEsc + " " + Configuration.EscapeParamValue(Credentials.UserName), new SingleCommand(), ct);
                                                                SendCommand("password " + realmEsc + " " + Configuration.EscapeParamValue(Credentials.Password), new SingleCommand(), ct);
                                                            }
                                                            break;
                                                    }
                                                }
                                            }
                                        }
                                        break;

                                    case "PKCS11ID-COUNT":
                                        // TODO: Implement.
                                        break;

                                    case "PROXY":
                                        // TODO: Implement.
                                        SendCommand("proxy NONE", new SingleCommand(), ct);
                                        break;

                                    case "REMOTE":
                                        {
                                            // Get action.
                                            var fields = msg[1].Split(FieldSeparators, 3 + 1);
                                            var e = new RemoteReportedEventArgs(
                                                fields[0].Trim(),
                                                fields.Length > 1 && int.TryParse(fields[1].Trim(), out var port) ? port : 0,
                                                fields.Length > 2 && ParameterValueAttribute.TryGetEnumByParameterValueAttribute<ProtoType>(fields[2].Trim(), out var proto) ? proto : ProtoType.UDP);
                                            RemoteReported?.Invoke(this, e);

                                            // Send reply message.
                                            SendCommand("remote " + e.Action.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "PK_SIGN":
                                        {
                                            // Get signature.
                                            var fields = msg[1].Split(FieldSeparators);
                                            var e = new SignRequestedEventArgs(
                                                Convert.FromBase64String(fields[0]),
                                                fields.Length > 1 && ParameterValueAttribute.TryGetEnumByParameterValueAttribute<SignAlgorithmType>(fields[1].Trim(), out var padding) ? padding : SignAlgorithmType.RSASignaturePKCS1Padding);
                                            SignRequested?.Invoke(this, e);

                                            // Send reply message.
                                            var sb = new StringBuilder();
                                            sb.Append("pk-sig\n");
                                            sb.Append(Convert.ToBase64String(e.Signature, Base64FormattingOptions.InsertLineBreaks).Replace("\r", ""));
                                            sb.Append("\nEND");
                                            SendCommand(sb.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "RSA_SIGN":
                                        {
                                            // Get signature.
                                            var e = new SignRequestedEventArgs(Convert.FromBase64String(msg[1]), SignAlgorithmType.RSASignaturePKCS1Padding);
                                            SignRequested?.Invoke(this, e);

                                            // Send reply message.
                                            var sb = new StringBuilder();
                                            sb.Append("rsa-sig\n");
                                            sb.Append(Convert.ToBase64String(e.Signature, Base64FormattingOptions.InsertLineBreaks).Replace("\r", ""));
                                            sb.Append("\nEND");
                                            SendCommand(sb.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "STATE":
                                        new StateCommand().ProcessData(msg[1], this);
                                        break;
                                }
                            }
                            else
                            {
                                Command cmd;
                                lock (Commands) cmd = Commands.Count > 0 ? Commands.Peek() : null;
                                if (cmd is MultilineCommand multilineCmd)
                                {
                                    if (line == "END")
                                    {
                                        // Multi-line response end.
                                        lock (Commands) Commands.Dequeue();
                                        multilineCmd.Finished.Set();
                                    }
                                    else
                                    {
                                        // One line of multi-line response.
                                        multilineCmd.ProcessData(line, this);
                                    }
                                }
                                else if (cmd is SingleCommand singleCmd)
                                {
                                    var msg = line.Split(MsgSeparators, 2);
                                    switch (msg[0].Trim())
                                    {
                                        case "SUCCESS":
                                            // Success response.
                                            lock (Commands) Commands.Dequeue();
                                            singleCmd.Success = true;
                                            singleCmd.Response = msg[1].Trim();
                                            singleCmd.Finished.Set();
                                            break;

                                        case "ERROR":
                                            // Error response.
                                            lock (Commands) Commands.Dequeue();
                                            singleCmd.Success = false;
                                            singleCmd.Response = msg[1].Trim();
                                            singleCmd.Finished.Set();
                                            break;
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex) { _Error = ex; }
                    finally
                    {
                        // Signal the monitor finished.
                        MonitorFinished.Set();
                    }
                }));
            _Monitor.Start();

            if (password != null)
            {
                // Send the password.
                var cmdResult = new SingleCommand();
                SendCommand(password, cmdResult, ct);
                WaitFor(cmdResult, ct);
            }

            // Wait for the interactive service to become ready.
            WaitFor(serviceReady, ct);

            // Wait for additional 100ms. Like OpenVPN GUI does.
            WaitFor(100, ct);
        }

        /// <summary>
        /// Set up automatic notification of bandwidth usage once every <paramref name="n"/> seconds; or turn it off
        /// </summary>
        /// <param name="n">Period (in seconds); <c>0</c> to turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetByteCount(int n, CancellationToken ct = default)
        {
            return WaitFor(QueueSetByteCount(n, ct), ct);
        }

        /// <summary>
        /// Set up automatic notification of bandwidth usage once every <paramref name="n"/> seconds; or turn it off (queue and continue)
        /// </summary>
        /// <param name="n">Period (in seconds); <c>0</c> to turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetByteCount(int n, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(String.Format("bytecount {0:D}", n), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Turn on or off real-time notification of echo messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableEcho(bool enable, CancellationToken ct = default)
        {
            return WaitFor(QueueEnableEcho(enable, ct), ct);
        }

        /// <summary>
        /// Turn on or off real-time notification of echo messages (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableEcho(bool enable, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(enable ? "echo on" : "echo off", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Print the current echo history list
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayEcho(CancellationToken ct = default)
        {
            WaitFor(QueueReplayEcho(ct), ct);
        }

        /// <summary>
        /// Print the current echo history list (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayEcho(CancellationToken ct = default)
        {
            var cmdResult = new EchoCommand();
            SendCommand("echo all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Atomically enable real-time notification, plus show any messages in history buffer
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableEcho(CancellationToken ct = default)
        {
            return WaitFor(QueueReplayAndEnableEcho(ct), ct);
        }

        /// <summary>
        /// Atomically enable real-time notification, plus show any messages in history buffer (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result objects</returns>
        public CombinedCommands QueueReplayAndEnableEcho(CancellationToken ct = default)
        {
            var cmdResult = new CombinedCommands { first = new SingleCommand(), second = new EchoCommand() };
            SendCommand("echo on all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Return current hold flag
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns><c>true</c> if hold flag is set; <c>false</c> otherwise</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "hold="</exception>
        /// <exception cref="FormatException">Hold flag is not a number</exception>
        /// <exception cref="OverflowException">Hold flag didn't fit inside 32-bit unsigned integer</exception>
        public bool GetHold(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("hold", cmdResult, ct);
            var result = WaitFor(cmdResult, ct);
            if (result.StartsWith("hold="))
                return uint.Parse(result.Substring(5)) != 0;
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Turn on or off hold flag so that future restarts will hold
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableHold(bool enable, CancellationToken ct = default)
        {
            return WaitFor(QueueEnableHold(enable, ct), ct);
        }

        /// <summary>
        /// Turn on or off hold flag so that future restarts will hold (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableHold(bool enable, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(enable ? "hold on" : "hold off", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Leave hold state and start OpenVPN, but do not alter the current hold flag setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReleaseHold(CancellationToken ct = default)
        {
            return WaitFor(QueueReleaseHold(ct), ct);
        }

        /// <summary>
        /// Leave hold state and start OpenVPN, but do not alter the current hold flag setting (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueReleaseHold(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("hold release", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Enable/disable real-time output of log messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableLog(bool enable, CancellationToken ct = default)
        {
            return WaitFor(QueueEnableLog(enable, ct), ct);
        }

        /// <summary>
        /// Enable/disable real-time output of log messages (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableLog(bool enable, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(enable ? "log on" : "log off", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Show the most recent <paramref name="n"/> lines of log file history
        /// </summary>
        /// <param name="n">Number of lines</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(int n, CancellationToken ct = default)
        {
            WaitFor(QueueReplayLog(n, ct), ct);
        }

        /// <summary>
        /// Show the most recent <paramref name="n"/> lines of log file history (queue and continue)
        /// </summary>
        /// <param name="n">Number of lines</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayLog(int n, CancellationToken ct = default)
        {
            var cmdResult = new LogCommand();
            SendCommand(String.Format("log {0:D}", n), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Show currently cached log file history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(CancellationToken ct = default)
        {
            WaitFor(QueueReplayLog(ct), ct);
        }

        /// <summary>
        /// Show currently cached log file history (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayLog(CancellationToken ct = default)
        {
            var cmdResult = new LogCommand();
            SendCommand("log all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Atomically show all currently cached log file history then enable real-time notification of new log file messages
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableLog(CancellationToken ct = default)
        {
            return WaitFor(QueueReplayAndEnableLog(ct), ct);
        }

        /// <summary>
        /// Atomically show all currently cached log file history then enable real-time notification of new log file messages (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public CombinedCommands QueueReplayAndEnableLog(CancellationToken ct = default)
        {
            var cmdResult = new CombinedCommands { first = new SingleCommand(), second = new LogCommand() };
            SendCommand("log on all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Show the current mute setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Mute setting</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "mute="</exception>
        /// <exception cref="FormatException">Mute setting is not a number</exception>
        /// <exception cref="OverflowException">Mute setting didn't fit inside 32-bit integer</exception>
        public int GetMute(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("mute", cmdResult, ct);
            var result = WaitFor(cmdResult, ct);
            if (result.StartsWith("mute="))
                return int.Parse(result.Substring(5));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Change the mute parameter
        /// </summary>
        /// <param name="n">Mute setting</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetMute(int n, CancellationToken ct = default)
        {
            return WaitFor(QueueSetMute(n, ct), ct);
        }

        /// <summary>
        /// Change the mute parameter (queue and continue)
        /// </summary>
        /// <param name="n">Mute setting</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetMute(int n, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(String.Format("mute {0:D}", n), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Shows the process ID of the current OpenVPN process
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>openvpn.exe process ID</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "pid="</exception>
        /// <exception cref="FormatException">Process ID is not a number</exception>
        /// <exception cref="OverflowException">Process ID didn't fit inside 32-bit integer</exception>
        public int GetProcessID(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("pid", cmdResult, ct);
            var result = WaitFor(cmdResult, ct);
            if (result.StartsWith("pid="))
                return int.Parse(result.Substring(4));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Forget passwords entered so far
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ForgetPasswords(CancellationToken ct = default)
        {
            return WaitFor(QueueForgetPasswords(ct), ct);
        }

        /// <summary>
        /// Forget passwords entered so far (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueForgetPasswords(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("forget-passwords", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Send a <paramref name="signal"/> signal to daemon
        /// </summary>
        /// <param name="signal">Signal to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SendSignal(SignalType signal, CancellationToken ct = default)
        {
            return WaitFor(QueueSendSignal(signal, ct), ct);
        }

        /// <summary>
        /// Send a <paramref name="signal"/> signal to daemon (queue and continue)
        /// </summary>
        /// <param name="signal">Signal to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSendSignal(SignalType signal, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(String.Format("signal {0}", Enum.GetName(typeof(SignalType), signal)), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Print current OpenVPN state
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayCurrentState(CancellationToken ct = default)
        {
            WaitFor(QueueReplayCurrentState(ct), ct);
        }

        /// <summary>
        /// Print current OpenVPN state (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayCurrentState(CancellationToken ct = default)
        {
            var cmdResult = new StateCommand();
            SendCommand("state", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Enable/disable real-time notification of state changes
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableState(bool enable, CancellationToken ct = default)
        {
            return WaitFor(QueueEnableState(enable, ct), ct);
        }

        /// <summary>
        /// Enable/disable real-time notification of state changes (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableState(bool enable, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(enable ? "state on" : "state off", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Print current state history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(CancellationToken ct = default)
        {
            WaitFor(QueueReplayState(ct), ct);
        }

        /// <summary>
        /// Print current state history (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayState(CancellationToken ct = default)
        {
            var cmdResult = new StateCommand();
            SendCommand("state all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Print the <paramref name="n"/> most recent state transitions
        /// </summary>
        /// <param name="n">Number of states</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(int n, CancellationToken ct = default)
        {
            WaitFor(QueueReplayState(n, ct), ct);
        }

        /// <summary>
        /// Print the <paramref name="n"/> most recent state transitions (queue and continue)
        /// </summary>
        /// <param name="n">Number of states</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayState(int n, CancellationToken ct = default)
        {
            var cmdResult = new StateCommand();
            SendCommand(String.Format("state {0:D}", n), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Atomically show state history while at the same time enable real-time state notification of future state transitions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableState(CancellationToken ct = default)
        {
            return WaitFor(QueueReplayAndEnableState(ct), ct);
        }

        /// <summary>
        /// Atomically show state history while at the same time enable real-time state notification of future state transitions (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public CombinedCommands QueueReplayAndEnableState(CancellationToken ct = default)
        {
            var cmdResult = new CombinedCommands { first = new SingleCommand(), second = new StateCommand() };
            SendCommand("state on all", cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Show the current verb setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Verbosity level</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "verb="</exception>
        /// <exception cref="FormatException">Verbosity level is not a number</exception>
        /// <exception cref="OverflowException">Verbosity level didn't fit inside 32-bit integer</exception>
        public int GetVerbosity(CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand("verb", cmdResult, ct);
            var result = WaitFor(cmdResult, ct);
            if (result.StartsWith("verb="))
                return int.Parse(result.Substring(5));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Change the verb parameter to <paramref name="n"/>
        /// </summary>
        /// <param name="n">Verbosity level</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetVerbosity(int n, CancellationToken ct = default)
        {
            return WaitFor(QueueSetVerbosity(n, ct), ct);
        }

        /// <summary>
        /// Change the verb parameter to <paramref name="n"/> (queue and continue)
        /// </summary>
        /// <param name="n">Verbosity level</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetVerbosity(int n, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(String.Format("verb {0:D}", n), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Show the current OpenVPN and Management Interface versions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Dictionary of versions</returns>
        public Dictionary<string, string> GetVersion(CancellationToken ct = default)
        {
            var cmd = new VersionCommand();
            SendCommand("version", cmd, ct);
            WaitFor(cmd, ct);
            return cmd.Version;
        }

        /// <summary>
        /// Change the Management Interface version to <paramref name="n"/>
        /// </summary>
        /// <param name="n">Management Interface version</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void SetVersion(int n, CancellationToken ct = default)
        {
            SendCommand(String.Format("version {0:D}", n), ct);
        }

        /// <summary>
        /// Set the --auth-retry setting to control how OpenVPN responds to username/password authentication errors
        /// </summary>
        /// <param name="authRetry">Authentication retry</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetAuthenticationRetry(AuthRetryType authRetry, CancellationToken ct = default)
        {
            return WaitFor(QueueSetAuthenticationRetry(authRetry, ct), ct);
        }

        /// <summary>
        /// Set the --auth-retry setting to control how OpenVPN responds to username/password authentication errors (queue and continue)
        /// </summary>
        /// <param name="authRetry">Authentication retry</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetAuthenticationRetry(AuthRetryType authRetry, CancellationToken ct = default)
        {
            var cmdResult = new SingleCommand();
            SendCommand(String.Format("auth-retry {0}", authRetry.GetParameterValue()), cmdResult, ct);
            return cmdResult;
        }

        /// <summary>
        /// Waits for the event
        /// </summary>
        /// <param name="waitHandle">Event to wait for</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="OperationCanceledException">The <paramref name="ct"/> was set.</exception>
        /// <exception cref="MonitorTerminatedException">Monitor terminated prematurely.</exception>
        private void WaitFor(WaitHandle waitHandle, CancellationToken ct = default)
        {
            switch (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, MonitorFinished, waitHandle }))
            {
                case 0: throw new OperationCanceledException();
                case 1: throw new MonitorTerminatedException(_Error);
            }
        }

        /// <summary>
        /// Waits for the amount of time
        /// </summary>
        /// <param name="timeout">Timeout to wait for in milliseconds (-1 for indefinite)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="OperationCanceledException">The <paramref name="ct"/> was set.</exception>
        /// <exception cref="MonitorTerminatedException">Monitor terminated prematurely.</exception>
        private void WaitFor(int timeout, CancellationToken ct = default)
        {
            switch (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, MonitorFinished }, timeout))
            {
                case 0: throw new OperationCanceledException();
                case 1: throw new MonitorTerminatedException(_Error);
            }
        }

        /// <summary>
        /// Waits for the command to finish and return its result
        /// </summary>
        /// <param name="cmdResult">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string WaitFor(SingleCommand cmdResult, CancellationToken ct = default)
        {
            // Await for the command to finish.
            WaitFor(cmdResult.Finished);

            if (cmdResult.Success)
                return cmdResult.Response;
            else
                throw new CommandException(cmdResult.Response);
        }

        /// <summary>
        /// Waits for the command to finish
        /// </summary>
        /// <param name="cmdResult">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        private void WaitFor(MultilineCommand cmdResult, CancellationToken ct = default)
        {
            // Await for the command to finish.
            WaitFor(cmdResult.Finished);
        }

        /// <summary>
        /// Waits for <c>cmdResult.second</c> command to finish and return <c>cmdResult.first</c> command result
        /// </summary>
        /// <param name="cmdResult">Pending command results</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string WaitFor(CombinedCommands cmdResult, CancellationToken ct = default)
        {
            // Await for the second command to finish.
            WaitFor(cmdResult.second.Finished);

            if (cmdResult.first.Success)
                return cmdResult.first.Response;
            else
                throw new CommandException(cmdResult.first.Response);
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="SessionStateException">Session is in the state of error and is not accepting new commands.</exception>
        private void SendCommand(string cmd, CancellationToken ct = default)
        {
            if (_Error != null)
                throw new SessionStateException(Resources.Strings.ErrorSessionState);

            lock (CommandsLock)
            {
                // Send the command.
                var binCmd = Encoding.UTF8.GetBytes(cmd + "\n");
                _Stream.Write(binCmd, 0, binCmd.Length, ct);
            }
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmdResult">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="SessionStateException">Session is in the state of error and is not accepting new commands.</exception>
        private void SendCommand(string cmd, Command cmdResult, CancellationToken ct = default)
        {
            if (_Error != null)
                throw new SessionStateException(Resources.Strings.ErrorSessionState);

            lock (CommandsLock)
            {
                lock (Commands)
                    Commands.Enqueue(cmdResult);

                // Send the command.
                var binCmd = Encoding.UTF8.GetBytes(cmd + "\n");
                _Stream.Write(binCmd, 0, binCmd.Length, ct);
            }
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmdResult">Pending command results</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="SessionStateException">Session is in the state of error and is not accepting new commands.</exception>
        private void SendCommand(string cmd, CombinedCommands cmdResult, CancellationToken ct = default)
        {
            if (_Error != null)
                throw new SessionStateException(Resources.Strings.ErrorSessionState);

            lock (CommandsLock)
            {
                lock (Commands)
                {
                    Commands.Enqueue(cmdResult.first);
                    Commands.Enqueue(cmdResult.second);
                }

                // Send the command.
                var binCmd = Encoding.UTF8.GetBytes(cmd + "\n");
                _Stream.Write(binCmd, 0, binCmd.Length, ct);
            }
        }

        #endregion

        #region IDisposable Support
        /// <summary>
        /// Flag to detect redundant <see cref="Dispose(bool)"/> calls.
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private bool disposedValue = false;

        /// <summary>
        /// Called to dispose the object.
        /// </summary>
        /// <param name="disposing">Dispose managed objects</param>
        /// <remarks>
        /// To release resources for inherited classes, override this method.
        /// Call <c>base.Dispose(disposing)</c> within it to release parent class resources, and release child class resources if <paramref name="disposing"/> parameter is <c>true</c>.
        /// This method can get called multiple times for the same object instance. When the child specific resources should be released only once, introduce a flag to detect redundant calls.
        /// </remarks>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (MonitorFinished != null)
                        MonitorFinished.Dispose();

                    if (_Stream != null)
                        _Stream.Dispose();
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting resources.
        /// </summary>
        /// <remarks>
        /// This method calls <see cref="Dispose(bool)"/> with <c>disposing</c> parameter set to <c>true</c>.
        /// To implement resource releasing override the <see cref="Dispose(bool)"/> method.
        /// </remarks>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
