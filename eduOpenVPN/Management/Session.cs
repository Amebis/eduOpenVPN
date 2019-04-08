/*
    eduOpenVPN - OpenVPN Management Library for eduVPN (and beyond)

    Copyright: 2017-2019 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
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
                var fields = data.Split(_field_separators, 1 + 1);
                session.EchoReceived?.Invoke(session, new EchoReceivedEventArgs(
                    int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                    fields.Length >= 2 ? fields[1].Trim() : null));
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
                var fields = data.Split(_msg_separators, 2 + 1);
                session.HoldReported?.Invoke(session, new HoldReportedEventArgs(
                    fields.Length >= 1 ? fields[0].Trim() : null,
                    fields.Length >= 2 && int.TryParse(fields[1].Trim(), out var hint) ? hint : 0));
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
                var fields = data.Split(_field_separators, 2 + 1);
                session.LogReported?.Invoke(session, new LogReportedEventArgs(
                    int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                    fields.Length >= 2 ?
                        (fields[1].IndexOf('I') >= 0 ? LogMessageFlags.Informational : 0) |
                        (fields[1].IndexOf('F') >= 0 ? LogMessageFlags.FatalError : 0) |
                        (fields[1].IndexOf('N') >= 0 ? LogMessageFlags.NonFatalError : 0) |
                        (fields[1].IndexOf('W') >= 0 ? LogMessageFlags.Warning : 0) |
                        (fields[1].IndexOf('D') >= 0 ? LogMessageFlags.Debug : 0)
                        : 0,
                    fields.Length >= 3 ? fields[2].Trim() : null));
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
                var fields = data.Split(_field_separators, 9 + 1);
                if (fields.Length >= 2)
                {
                    OpenVPNStateType state;
                    try { state = ParameterValueAttribute.GetEnumByParameterValueAttribute<OpenVPNStateType>(fields[1].Trim()); }
                    catch { state = default(OpenVPNStateType); }

                    session.StateReported?.Invoke(session, new StateReportedEventArgs(
                        int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                        state,
                        fields.Length >= 3 ? fields[2].Trim() : null,
                        fields.Length >= 4 && IPAddress.TryParse(fields[3].Trim(), out var address) ? address : null,
                        fields.Length >= 9 && IPAddress.TryParse(fields[8].Trim(), out var ipv6_address) ? ipv6_address : null,
                        fields.Length >= 6 && IPAddress.TryParse(fields[4].Trim(), out var remote_address) && int.TryParse(fields[5].Trim(), out var remote_port) ? new IPEndPoint(remote_address, remote_port) : null,
                        fields.Length >= 8 && IPAddress.TryParse(fields[6].Trim(), out var local_address) && int.TryParse(fields[7].Trim(), out var local_port) ? new IPEndPoint(local_address, local_port) : null));
                }
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
                var fields = data.Split(_msg_separators, 1 + 1);
                if (fields.Length >= 1)
                    Version[fields[0]] = fields.Length >= 2 ? fields[1].Trim() : null;
            }
        }

        #endregion

        #region Fields

        /// <summary>
        /// Used to convert Unix timestamps into <see cref="DateTimeOffset"/>
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly DateTimeOffset _epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, new TimeSpan(0, 0, 0));

        /// <summary>
        /// Message separators
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly char[] _msg_separators = new char[] { ':' };

        /// <summary>
        /// Field separators
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly char[] _field_separators = new char[] { ',' };

        /// <summary>
        /// Queue of pending commands
        /// </summary>
        private Queue<Command> _commands;

        /// <summary>
        /// Lock to serialize command submission
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private object _command_lock;

        /// <summary>
        /// Waitable event to signal the monitor finished
        /// </summary>
        private EventWaitHandle _monitor_finished = new EventWaitHandle(false, EventResetMode.ManualReset);

        /// <summary>
        /// Cached credentials
        /// </summary>
        private NetworkCredential _credentials;

        #endregion

        #region Properties

        /// <summary>
        /// Network stream to OpenVPN Management console
        /// </summary>
        public NetworkStream Stream { get => _stream; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private NetworkStream _stream;

        /// <summary>
        /// Session monitor
        /// </summary>
        public Thread Monitor { get => _monitor; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Thread _monitor;

        /// <summary>
        /// Session monitor error
        /// </summary>
        public Exception Error { get => _error; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Exception _error;

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
        public event EventHandler<RSASignRequestedEventArgs> RSASignRequested;

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
                    _credentials = null;
                }
            };

            AuthenticationFailed += (object sender, AuthenticationEventArgs e) =>
            {
                // Reset cached credentials to force user re-prompting.
                _credentials = null;
            };

            AuthenticationTokenReported += (object sender, AuthenticationTokenReportedEventArgs e) =>
            {
                if (_credentials != null)
                {
                    // Save authentication token. OpenVPN accepts it as the password on reauthentications.
                    _credentials.SecurePassword = e.Token;
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
        public void Start(NetworkStream stream, string password, CancellationToken ct = default(CancellationToken))
        {
            _stream = stream;
            var reader = new StreamReader(_stream, Encoding.UTF8, false);
            var service_ready = new EventWaitHandle(false, EventResetMode.ManualReset);

            if (password != null)
            {
                // Read the password prompt.
                var buffer = new char[15];
                var read_task = reader.ReadBlockAsync(buffer, 0, buffer.Length);
                try { read_task.Wait(ct); }
                catch (AggregateException ex) { throw ex.InnerException; }
                if (buffer.Length < 15 || new String(buffer) != "ENTER PASSWORD:")
                    throw new UnexpectedReplyException(new String(buffer));
            }

            _commands = new Queue<Command>();
            _command_lock = new object();

            // Spawn the monitor.
            _monitor = new Thread(new ThreadStart(
                () =>
                {
                    try
                    {
                        for (;;)
                        {
                            ct.ThrowIfCancellationRequested();

                            // Read one line.
                            var read_task = reader.ReadLineAsync();
                            try { read_task.Wait(ct); }
                            catch (AggregateException ex) { throw ex.InnerException; }
                            var line = read_task.Result;

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
                                var msg = line.Substring(1).Split(_msg_separators, 2);
                                switch (msg[0].Trim())
                                {
                                    case "BYTECOUNT":
                                        {
                                            var fields = msg[1].Split(_field_separators, 2 + 1);
                                            ByteCountReported?.Invoke(this, new ByteCountReportedEventArgs(
                                                fields.Length >= 1 && ulong.TryParse(fields[0].Trim(), out var bytes_in) ? bytes_in : 0,
                                                fields.Length >= 2 && ulong.TryParse(fields[1].Trim(), out var bytes_out) ? bytes_out : 0
                                            ));
                                        }
                                        break;

                                    case "BYTECOUNT_CLI":
                                        {
                                            var fields = msg[1].Split(_field_separators, 3 + 1);
                                            ByteCountClientReported?.Invoke(this, new ByteCountClientReportedEventArgs(
                                                fields.Length >= 1 && uint.TryParse(fields[0].Trim(), out var cid) ? cid : 0,
                                                fields.Length >= 2 && ulong.TryParse(fields[1].Trim(), out var bytes_in) ? bytes_in : 0,
                                                fields.Length >= 3 && ulong.TryParse(fields[2].Trim(), out var bytes_out) ? bytes_out : 0
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
                                        service_ready.Set();
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
                                                if (param.Count >= 3 && param[0] == "Need")
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
                                                                if (_credentials == null)
                                                                {
                                                                    // TODO: Support Static challenge/response protocol (PASSWORD:Need 'Auth' username/password SC:<ECHO>,<TEXT>)

                                                                    var e = new UsernamePasswordAuthenticationRequestedEventArgs(param[1]);
                                                                    UsernamePasswordAuthenticationRequested?.Invoke(this, e);
                                                                    if (e.Username == null || e.Password == null)
                                                                        throw new OperationCanceledException();

                                                                    // Prepare new credentials.
                                                                    _credentials = new NetworkCredential(e.Username, "") { SecurePassword = e.Password };
                                                                }

                                                                // Send reply messages.
                                                                var realm_esc = Configuration.EscapeParamValue(param[1]);
                                                                SendCommand("username " + realm_esc + " " + Configuration.EscapeParamValue(_credentials.UserName), new SingleCommand(), ct);
                                                                SendCommand("password " + realm_esc + " " + Configuration.EscapeParamValue(_credentials.Password), new SingleCommand(), ct);
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
                                            var fields = msg[1].Split(_field_separators, 3 + 1);
                                            var e = new RemoteReportedEventArgs(
                                                fields.Length >= 1 ? fields[0].Trim() : null,
                                                fields.Length >= 2 && int.TryParse(fields[1].Trim(), out var port) ? port : 0,
                                                fields.Length >= 3 && ParameterValueAttribute.TryGetEnumByParameterValueAttribute<ProtoType>(fields[2].Trim(), out var proto) ? proto : ProtoType.UDP);
                                            RemoteReported?.Invoke(this, e);

                                            // Send reply message.
                                            SendCommand("remote " + e.Action.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "RSA_SIGN":
                                        {
                                            // Get signature.
                                            var e = new RSASignRequestedEventArgs(Convert.FromBase64String(msg[1]));
                                            RSASignRequested?.Invoke(this, e);

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
                                lock (_commands) cmd = _commands.Count > 0 ? _commands.Peek() : null;
                                if (cmd is MultilineCommand cmd_multiline)
                                {
                                    if (line == "END")
                                    {
                                        // Multi-line response end.
                                        lock (_commands) _commands.Dequeue();
                                        cmd_multiline.Finished.Set();
                                    }
                                    else
                                    {
                                        // One line of multi-line response.
                                        cmd_multiline.ProcessData(line, this);
                                    }
                                }
                                else if (cmd is SingleCommand cmd_single)
                                {
                                    var msg = line.Split(_msg_separators, 2);
                                    switch (msg[0].Trim())
                                    {
                                        case "SUCCESS":
                                            // Success response.
                                            lock (_commands) _commands.Dequeue();
                                            cmd_single.Success = true;
                                            cmd_single.Response = msg[1].Trim();
                                            cmd_single.Finished.Set();
                                            break;

                                        case "ERROR":
                                            // Error response.
                                            lock (_commands) _commands.Dequeue();
                                            cmd_single.Success = false;
                                            cmd_single.Response = msg[1].Trim();
                                            cmd_single.Finished.Set();
                                            break;
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex) { _error = ex; }
                    finally
                    {
                        // Signal the monitor finished.
                        _monitor_finished.Set();
                    }
                }));
            _monitor.Start();

            if (password != null)
            {
                // Send the password.
                var cmd_result = new SingleCommand();
                SendCommand(password, cmd_result, ct);
                WaitFor(cmd_result, ct);
            }

            // Wait for the interactive service to become ready.
            WaitFor(service_ready, ct);

            // Wait for additional 100ms. Like OpenVPN GUI does.
            WaitFor(100, ct);
        }

        /// <summary>
        /// Set up automatic notification of bandwidth usage once every <paramref name="n"/> seconds; or turn it off
        /// </summary>
        /// <param name="n">Period (in seconds); <c>0</c> to turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetByteCount(int n, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueSetByteCount(n, ct), ct);
        }

        /// <summary>
        /// Set up automatic notification of bandwidth usage once every <paramref name="n"/> seconds; or turn it off (queue and continue)
        /// </summary>
        /// <param name="n">Period (in seconds); <c>0</c> to turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetByteCount(int n, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(String.Format("bytecount {0:D}", n), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Turn on or off real-time notification of echo messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableEcho(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueEnableEcho(enable, ct), ct);
        }

        /// <summary>
        /// Turn on or off real-time notification of echo messages (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableEcho(bool enable, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(enable ? "echo on" : "echo off", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Print the current echo history list
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayEcho(CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayEcho(ct), ct);
        }

        /// <summary>
        /// Print the current echo history list (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayEcho(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new EchoCommand();
            SendCommand("echo all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Atomically enable real-time notification, plus show any messages in history buffer
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableEcho(CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueReplayAndEnableEcho(ct), ct);
        }

        /// <summary>
        /// Atomically enable real-time notification, plus show any messages in history buffer (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result objects</returns>
        public CombinedCommands QueueReplayAndEnableEcho(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new CombinedCommands { first = new SingleCommand(), second = new EchoCommand() };
            SendCommand("echo on all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Return current hold flag
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns><c>true</c> if hold flag is set; <c>false</c> otherwise</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "hold="</exception>
        public bool GetHold(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("hold", cmd_result, ct);
            var result = WaitFor(cmd_result, ct);
            if (result.StartsWith("hold="))
                return (uint)new UInt32Converter().ConvertFromString(result.Substring(5)) != 0;
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Turn on or off hold flag so that future restarts will hold
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableHold(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueEnableHold(enable, ct), ct);
        }

        /// <summary>
        /// Turn on or off hold flag so that future restarts will hold (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableHold(bool enable, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(enable ? "hold on" : "hold off", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Leave hold state and start OpenVPN, but do not alter the current hold flag setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReleaseHold(CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueReleaseHold(ct), ct);
        }

        /// <summary>
        /// Leave hold state and start OpenVPN, but do not alter the current hold flag setting (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueReleaseHold(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("hold release", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Enable/disable real-time output of log messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableLog(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueEnableLog(enable, ct), ct);
        }

        /// <summary>
        /// Enable/disable real-time output of log messages (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableLog(bool enable, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(enable ? "log on" : "log off", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Show the most recent <paramref name="n"/> lines of log file history
        /// </summary>
        /// <param name="n">Number of lines</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(int n, CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayLog(n, ct), ct);
        }

        /// <summary>
        /// Show the most recent <paramref name="n"/> lines of log file history (queue and continue)
        /// </summary>
        /// <param name="n">Number of lines</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayLog(int n, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new LogCommand();
            SendCommand(String.Format("log {0:D}", n), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Show currently cached log file history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayLog(ct), ct);
        }

        /// <summary>
        /// Show currently cached log file history (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayLog(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new LogCommand();
            SendCommand("log all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Atomically show all currently cached log file history then enable real-time notification of new log file messages
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableLog(CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueReplayAndEnableLog(ct), ct);
        }

        /// <summary>
        /// Atomically show all currently cached log file history then enable real-time notification of new log file messages (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public CombinedCommands QueueReplayAndEnableLog(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new CombinedCommands { first = new SingleCommand(), second = new LogCommand() };
            SendCommand("log on all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Show the current mute setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Mute setting</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "mute="</exception>
        public int GetMute(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("mute", cmd_result, ct);
            var result = WaitFor(cmd_result, ct);
            if (result.StartsWith("mute="))
                return (int)new Int32Converter().ConvertFromString(result.Substring(5));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Change the mute parameter
        /// </summary>
        /// <param name="n">Mute setting</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetMute(int n, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueSetMute(n, ct), ct);
        }

        /// <summary>
        /// Change the mute parameter (queue and continue)
        /// </summary>
        /// <param name="n">Mute setting</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetMute(int n, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(String.Format("mute {0:D}", n), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Shows the process ID of the current OpenVPN process
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>openvpn.exe process ID</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "pid="</exception>
        public int GetProcessID(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("pid", cmd_result, ct);
            var result = WaitFor(cmd_result, ct);
            if (result.StartsWith("pid="))
                return (int)new Int32Converter().ConvertFromString(result.Substring(4));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Forget passwords entered so far
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ForgetPasswords(CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueForgetPasswords(ct), ct);
        }

        /// <summary>
        /// Forget passwords entered so far (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueForgetPasswords(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("forget-passwords", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Send a <paramref name="signal"/> signal to daemon
        /// </summary>
        /// <param name="signal">Signal to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SendSignal(SignalType signal, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueSendSignal(signal, ct), ct);
        }

        /// <summary>
        /// Send a <paramref name="signal"/> signal to daemon (queue and continue)
        /// </summary>
        /// <param name="signal">Signal to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSendSignal(SignalType signal, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(String.Format("signal {0}", Enum.GetName(typeof(SignalType), signal)), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Print current OpenVPN state
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayCurrentState(CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayCurrentState(ct), ct);
        }

        /// <summary>
        /// Print current OpenVPN state (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayCurrentState(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new StateCommand();
            SendCommand("state", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Enable/disable real-time notification of state changes
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableState(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueEnableState(enable, ct), ct);
        }

        /// <summary>
        /// Enable/disable real-time notification of state changes (queue and continue)
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueEnableState(bool enable, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(enable ? "state on" : "state off", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Print current state history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayState(ct), ct);
        }

        /// <summary>
        /// Print current state history (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayState(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new StateCommand();
            SendCommand("state all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Print the <paramref name="n"/> most recent state transitions
        /// </summary>
        /// <param name="n">Number of states</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(int n, CancellationToken ct = default(CancellationToken))
        {
            WaitFor(QueueReplayState(n, ct), ct);
        }

        /// <summary>
        /// Print the <paramref name="n"/> most recent state transitions (queue and continue)
        /// </summary>
        /// <param name="n">Number of states</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public MultilineCommand QueueReplayState(int n, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new StateCommand();
            SendCommand(String.Format("state {0:D}", n), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Atomically show state history while at the same time enable real-time state notification of future state transitions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableState(CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueReplayAndEnableState(ct), ct);
        }

        /// <summary>
        /// Atomically show state history while at the same time enable real-time state notification of future state transitions (queue and continue)
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public CombinedCommands QueueReplayAndEnableState(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new CombinedCommands { first = new SingleCommand(), second = new StateCommand() };
            SendCommand("state on all", cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Show the current verb setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Verbosity level</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "verb="</exception>
        public int GetVerbosity(CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand("verb", cmd_result, ct);
            var result = WaitFor(cmd_result, ct);
            if (result.StartsWith("verb="))
                return (int)new Int32Converter().ConvertFromString(result.Substring(5));
            else
                throw new UnexpectedReplyException(result);
        }

        /// <summary>
        /// Change the verb parameter to <paramref name="n"/>
        /// </summary>
        /// <param name="n">Verbosity level</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetVerbosity(int n, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueSetVerbosity(n, ct), ct);
        }

        /// <summary>
        /// Change the verb parameter to <paramref name="n"/> (queue and continue)
        /// </summary>
        /// <param name="n">Verbosity level</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetVerbosity(int n, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(String.Format("verb {0:D}", n), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Show the current OpenVPN and Management Interface versions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Dictionary of versions</returns>
        public Dictionary<string, string> GetVersion(CancellationToken ct = default(CancellationToken))
        {
            var cmd = new VersionCommand();
            SendCommand("version", cmd, ct);
            WaitFor(cmd, ct);
            return cmd.Version;
        }

        /// <summary>
        /// Set the --auth-retry setting to control how OpenVPN responds to username/password authentication errors
        /// </summary>
        /// <param name="auth_retry">Authentication retry</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetAuthenticationRetry(AuthRetryType auth_retry, CancellationToken ct = default(CancellationToken))
        {
            return WaitFor(QueueSetAuthenticationRetry(auth_retry, ct), ct);
        }

        /// <summary>
        /// Set the --auth-retry setting to control how OpenVPN responds to username/password authentication errors (queue and continue)
        /// </summary>
        /// <param name="auth_retry">Authentication retry</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Waitable command result object</returns>
        public SingleCommand QueueSetAuthenticationRetry(AuthRetryType auth_retry, CancellationToken ct = default(CancellationToken))
        {
            var cmd_result = new SingleCommand();
            SendCommand(String.Format("auth-retry {0}", auth_retry.GetParameterValue()), cmd_result, ct);
            return cmd_result;
        }

        /// <summary>
        /// Waits for the event
        /// </summary>
        /// <param name="wait_handle">Event to wait for</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="OperationCanceledException">The <paramref name="ct"/> was set.</exception>
        /// <exception cref="MonitorTerminatedException">Monitor terminated prematurely.</exception>
        private void WaitFor(WaitHandle wait_handle, CancellationToken ct = default(CancellationToken))
        {
            switch (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, _monitor_finished, wait_handle }))
            {
                case 0: throw new OperationCanceledException();
                case 1: throw new MonitorTerminatedException(_error);
            }
        }

        /// <summary>
        /// Waits for the amount of time
        /// </summary>
        /// <param name="timeout">Timeout to wait for in milliseconds (-1 for indefinite)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="OperationCanceledException">The <paramref name="ct"/> was set.</exception>
        /// <exception cref="MonitorTerminatedException">Monitor terminated prematurely.</exception>
        private void WaitFor(int timeout, CancellationToken ct = default(CancellationToken))
        {
            switch (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, _monitor_finished }, timeout))
            {
                case 0: throw new OperationCanceledException();
                case 1: throw new MonitorTerminatedException(_error);
            }
        }

        /// <summary>
        /// Waits for the command to finish and return its result
        /// </summary>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string WaitFor(SingleCommand cmd_result, CancellationToken ct = default(CancellationToken))
        {
            // Await for the command to finish.
            WaitFor(cmd_result.Finished);

            if (cmd_result.Success)
                return cmd_result.Response;
            else
                throw new CommandException(cmd_result.Response);
        }

        /// <summary>
        /// Waits for the command to finish
        /// </summary>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        private void WaitFor(MultilineCommand cmd_result, CancellationToken ct = default(CancellationToken))
        {
            // Await for the command to finish.
            WaitFor(cmd_result.Finished);
        }

        /// <summary>
        /// Waits for <c>cmd_result.second</c> command to finish and return <c>cmd_result.first</c> command result
        /// </summary>
        /// <param name="cmd_result">Pending command results</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string WaitFor(CombinedCommands cmd_result, CancellationToken ct = default(CancellationToken))
        {
            // Await for the second command to finish.
            WaitFor(cmd_result.second.Finished);

            if (cmd_result.first.Success)
                return cmd_result.first.Response;
            else
                throw new CommandException(cmd_result.first.Response);
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="SessionStateException">Session is in the state of error and is not accepting new commands.</exception>
        private void SendCommand(string cmd, Command cmd_result, CancellationToken ct = default(CancellationToken))
        {
            if (_error != null)
                throw new SessionStateException(Resources.Strings.ErrorSessionState);

            lock (_command_lock)
            {
                lock (_commands)
                    _commands.Enqueue(cmd_result);

                // Send the command.
                var cmd_bin = Encoding.UTF8.GetBytes(cmd + "\n");
                var write_task = _stream.WriteAsync(cmd_bin, 0, cmd_bin.Length, ct);
                try { write_task.Wait(ct); }
                catch (AggregateException ex) { throw ex.InnerException; }
            }
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result">Pending command results</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <exception cref="SessionStateException">Session is in the state of error and is not accepting new commands.</exception>
        private void SendCommand(string cmd, CombinedCommands cmd_result, CancellationToken ct = default(CancellationToken))
        {
            if (_error != null)
                throw new SessionStateException(Resources.Strings.ErrorSessionState);

            lock (_command_lock)
            {
                lock (_commands)
                {
                    _commands.Enqueue(cmd_result.first);
                    _commands.Enqueue(cmd_result.second);
                }

                // Send the command.
                var cmd_bin = Encoding.UTF8.GetBytes(cmd + "\n");
                var write_task = _stream.WriteAsync(cmd_bin, 0, cmd_bin.Length, ct);
                try { write_task.Wait(ct); }
                catch (AggregateException ex) { throw ex.InnerException; }
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
                    if (_monitor_finished != null)
                        _monitor_finished.Dispose();

                    if (_stream != null)
                        _stream.Dispose();
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
