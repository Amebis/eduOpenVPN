﻿/*
    eduOpenVPN - An OpenVPN Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        private class Command : IDisposable
        {
            /// <summary>
            /// Event to wait for command completition.
            /// </summary>
            public EventWaitHandle Finished = new EventWaitHandle(false, EventResetMode.ManualReset);

            #region IDisposable Support
            private bool disposedValue = false; // To detect redundant calls

            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                        Finished.Dispose();

                    disposedValue = true;
                }
            }

            // This code added to correctly implement the disposable pattern.
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
        private class SingleCommand : Command
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
        private class MultilineCommand : Command
        {
            /// <summary>
            /// Process one line of data returned from command
            /// </summary>
            /// <param name="data">Message data</param>
            /// <param name="event_sink">Event sink to notify of real-time messages</param>
            public virtual void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// "echo" command
        /// </summary>
        private class EchoCommand : MultilineCommand
        {
            public override void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                var fields = Encoding.UTF8.GetString(data).Split(new char[] { ',' }, 1 + 1);
                event_sink.OnEcho(
                    int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                    fields.Length >= 2 ? fields[1].Trim() : null);
            }
        }

        /// <summary>
        /// "hold" command
        /// </summary>
        private class HoldCommand : MultilineCommand
        {
            public override void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                var fields = Encoding.UTF8.GetString(data).Split(new char[] { ':' }, 2 + 1);
                event_sink.OnHold(
                    fields.Length >= 1 ? fields[0].Trim() : null,
                    fields.Length >= 2 && int.TryParse(fields[1].Trim(), out var hint) ? hint : 0);
            }
        }

        /// <summary>
        /// "log" command
        /// </summary>
        private class LogCommand : MultilineCommand
        {
            public override void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                var fields = Encoding.UTF8.GetString(data).Split(new char[] { ',' }, 2 + 1);
                event_sink.OnLog(
                    int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                    fields.Length >= 2 ?
                        (fields[1].IndexOf('I') >= 0 ? LogMessageFlags.Informational : 0) |
                        (fields[1].IndexOf('F') >= 0 ? LogMessageFlags.FatalError : 0) |
                        (fields[1].IndexOf('N') >= 0 ? LogMessageFlags.NonFatalError : 0) |
                        (fields[1].IndexOf('W') >= 0 ? LogMessageFlags.Warning : 0) |
                        (fields[1].IndexOf('D') >= 0 ? LogMessageFlags.Debug : 0)
                        : 0,
                    fields.Length >= 3 ? fields[2].Trim() : null);
            }
        }

        /// <summary>
        /// "state" command
        /// </summary>
        private class StateCommand : MultilineCommand
        {
            public override void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                var fields = Encoding.UTF8.GetString(data).Split(new char[] { ',' }, 9 + 1);
                if (fields.Length >= 2)
                {
                    OpenVPNStateType state;
                    try { state = ParameterValueAttribute.GetEnumByParameterValueAttribute<OpenVPNStateType>(fields[1].Trim()); }
                    catch (Exception) { state = OpenVPNStateType.Unknown; }

                    event_sink.OnState(
                        int.TryParse(fields[0].Trim(), out var unix_time) ? _epoch.AddSeconds(unix_time) : DateTimeOffset.UtcNow,
                        state,
                        fields.Length >= 3 ? fields[2].Trim() : null,
                        fields.Length >= 4 && IPAddress.TryParse(fields[3].Trim(), out var address) ? address : null,
                        fields.Length >= 9 && IPAddress.TryParse(fields[8].Trim(), out var ipv6_address) ? ipv6_address : null,
                        fields.Length >= 6 && IPAddress.TryParse(fields[4].Trim(), out var remote_address) && int.TryParse(fields[5].Trim(), out var remote_port) ? new IPEndPoint(remote_address, remote_port) : null,
                        fields.Length >= 8 && IPAddress.TryParse(fields[6].Trim(), out var local_address) && int.TryParse(fields[7].Trim(), out var local_port) ? new IPEndPoint(local_address, local_port) : null);
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
            public Dictionary<string, string> Version { get => _version; }
            private Dictionary<string, string> _version = new Dictionary<string, string>();

            public override void ProcessData(byte[] data, ISessionNotifications event_sink)
            {
                var fields = Encoding.UTF8.GetString(data).Split(new char[] { ':' }, 1 + 1);
                if (fields.Length >= 1)
                    _version[fields[0]] = fields.Length >= 2 ? fields[1].Trim() : null;
            }
        }

        #endregion

        #region Fields

        /// <summary>
        /// Used to convert Unix timestamps into <c>DateTimeOffset</c>
        /// </summary>
        private static readonly DateTimeOffset _epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, new TimeSpan(0, 0, 0));

        /// <summary>
        /// Queue of pending commands
        /// </summary>
        private Queue<Command> _commands;

        /// <summary>
        /// Lock to serialize command submission
        /// </summary>
        private object _command_lock;

        #endregion

        #region Properties

        /// <summary>
        /// Network stream to OpenVPN Management console
        /// </summary>
        public NetworkStream Stream { get => _stream; }
        private NetworkStream _stream;

        /// <summary>
        /// Session monitor
        /// </summary>
        public Thread Monitor { get => _monitor; }
        private Thread _monitor;

        #endregion

        #region Methods

        /// <summary>
        /// Starts an OpenVPN Management console session
        /// </summary>
        /// <param name="stream"><c>NetworkStream</c> of already established connection</param>
        /// <param name="password">OpenVPN Management interface password</param>
        /// <param name="event_sink">Event sink to notify of real-time messages</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void Start(NetworkStream stream, string password, ISessionNotifications event_sink, CancellationToken ct = default(CancellationToken))
        {
            _stream = stream;
#if !DEBUG
            _stream.WriteTimeout = 3000;
            _stream.ReadTimeout = 3000;
#endif

            _commands = new Queue<Command>();
            _command_lock = new object();

            // Spawn the monitor.
            var auth_req = new EventWaitHandle(false, EventResetMode.ManualReset);
            _monitor = new Thread(new ThreadStart(
                () =>
                {
                    var buffer = new byte[1048576];
                    var queue = new byte[0];

                    while (!ct.IsCancellationRequested)
                    {
                        {
                            // Read available data.
                            var read_task = _stream.ReadAsync(buffer, 0, buffer.Length, ct);
                            try { read_task.Wait(ct); }
                            catch (OperationCanceledException) { return; }
                            catch (AggregateException ex) { throw ex.InnerException; }

                            // Append it to the queue.
                            var queue_new = new byte[queue.LongLength + read_task.Result];
                            Array.Copy(queue, queue_new, queue.LongLength);
                            Array.Copy(buffer, 0, queue_new, queue.LongLength, read_task.Result);
                            queue = queue_new;
                        }

                        long offset = 0;
                        while (offset < queue.LongLength)
                        {
                            if (ct.IsCancellationRequested) return;

                            Command cmd;
                            lock (_commands) cmd = _commands.Count > 0 ? _commands.Peek() : null;

                            if (queue[offset] == '>')
                            {
                                // Real-time notification message.

                                // Find LF (or CR-LF).
                                long id_start = offset + 1, id_end = -1, data_start = -1, msg_end = -1, msg_next = -1;
                                for (long i = id_start; i < queue.LongLength; i++)
                                {
                                    long next_char;
                                    if (id_end < 0 && queue[i] == ':') { data_start = (id_end = i) + 1; }
                                    else if (queue[i] == '\n') { msg_next = (msg_end = i) + 1; break; }
                                    else if (queue[i] == '\r' && (next_char = i + 1) < queue.LongLength && queue[next_char] == '\n') { msg_next = (msg_end = i) + 2; break; }
                                }
                                if (msg_end < 0)
                                {
                                    // Message is incomplete. We need more data.
                                    break;
                                }
                                if (id_end < 0)
                                {
                                    // Semicolon separator missing?!
                                    data_start = id_end = msg_end;
                                }

                                // Parse message.
                                switch (Encoding.ASCII.GetString(queue.SubArray(id_start, id_end - id_start)).Trim())
                                {
                                    case "BYTECOUNT":
                                        {
                                            var fields = Encoding.ASCII.GetString(queue.SubArray(data_start, msg_end - data_start)).Split(new char[] { ',' }, 2 + 1);
                                            event_sink.OnByteCount(
                                                fields.Length >= 1 && ulong.TryParse(fields[0].Trim(), out var bytes_in) ? bytes_in : 0,
                                                fields.Length >= 2 && ulong.TryParse(fields[1].Trim(), out var bytes_out) ? bytes_out : 0);
                                        }
                                        break;

                                    case "BYTECOUNT_CLI":
                                        {
                                            var fields = Encoding.ASCII.GetString(queue.SubArray(data_start, msg_end - data_start)).Split(new char[] { ',' }, 3 + 1);
                                            event_sink.OnByteCountClient(
                                                fields.Length >= 1 && uint.TryParse(fields[0].Trim(), out var cid) ? cid : 0,
                                                fields.Length >= 2 && ulong.TryParse(fields[1].Trim(), out var bytes_in) ? bytes_in : 0,
                                                fields.Length >= 3 && ulong.TryParse(fields[2].Trim(), out var bytes_out) ? bytes_out : 0);
                                        }
                                        break;

                                    case "CLIENT":
                                        // TODO: Implement.
                                        break;

                                    case "CRV1":
                                        // TODO: Implement.
                                        break;

                                    case "ECHO":
                                        new EchoCommand().ProcessData(queue.SubArray(data_start, msg_end - data_start), event_sink);
                                        break;

                                    case "FATAL":
                                        event_sink.OnFatal(Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start)));
                                        break;

                                    case "HOLD":
                                        new HoldCommand().ProcessData(queue.SubArray(data_start, msg_end - data_start), event_sink);
                                        break;

                                    case "INFO":
                                        event_sink.OnInfo(Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start)));
                                        break;

                                    case "LOG":
                                        new LogCommand().ProcessData(queue.SubArray(data_start, msg_end - data_start), event_sink);
                                        break;

                                    case "NEED-OK":
                                        // TODO: Implement.
                                        break;

                                    case "NEED-CERTIFICATE":
                                        {
                                            // Get certificate.
                                            var certificate = event_sink.OnNeedCertificate(Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start)));

                                            // Reply with certificate command.
                                            var sb = new StringBuilder();
                                            sb.Append("certificate\n-----BEGIN CERTIFICATE-----\n");
                                            sb.Append(Convert.ToBase64String(certificate.GetRawCertData(), Base64FormattingOptions.InsertLineBreaks).Replace("\r", ""));
                                            sb.Append("\n-----END CERTIFICATE-----\nEND");
                                            SendCommand(sb.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "NEED-STR":
                                        // TODO: Implement.
                                        break;

                                    case "PASSWORD":
                                        {
                                            var data = Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start));
                                            if (data.StartsWith("Need "))
                                            {
                                                if (data.EndsWith(" password"))
                                                {
                                                    var realm = data.Substring(5, data.Length - 14).Trim(new char[] { '\'' });
                                                    event_sink.OnNeedAuthentication(realm, out var pwd);

                                                }
                                                else if (data.EndsWith(" username/password"))
                                                {
                                                    var realm = data.Substring(5, data.Length - 23).Trim(new char[] { '\'' });
                                                    event_sink.OnNeedAuthentication(realm, out var user, out var pwd);
                                                }

                                                // TODO: Support Static challenge/response protocol (PASSWORD:Need 'Auth' username/password SC:<ECHO>,<TEXT>)
                                            }
                                            else if (data.StartsWith("Verification Failed: "))
                                                event_sink.OnAuthenticationFailed(data.Substring(21).Trim(new char[] { '\'' }));
                                        }
                                        break;

                                    case "PROXY":
                                        // TODO: Implement.
                                        break;

                                    case "REMOTE":
                                        // TODO: Implement.
                                        break;

                                    case "RSA_SIGN":
                                        {
                                            // Get signature.
                                            var signature = event_sink.OnRSASign(Convert.FromBase64String(Encoding.ASCII.GetString(queue.SubArray(data_start, msg_end - data_start))));

                                            // Send reply message.
                                            var sb = new StringBuilder();
                                            sb.Append("rsa-sig\n");
                                            sb.Append(Convert.ToBase64String(signature, Base64FormattingOptions.InsertLineBreaks).Replace("\r", ""));
                                            sb.Append("\nEND");
                                            SendCommand(sb.ToString(), new SingleCommand(), ct);
                                        }
                                        break;

                                    case "STATE":
                                        new StateCommand().ProcessData(queue.SubArray(data_start, msg_end - data_start), event_sink);
                                        break;
                                }

                                offset = msg_next;
                            }
                            else if (cmd is MultilineCommand cmd_multiline)
                            {
                                // Find LF (or CR-LF).
                                long msg_end = -1, msg_next = -1;
                                for (long i = offset; i < queue.LongLength; i++)
                                {
                                    long next_char;
                                    if (queue[i] == '\n') { msg_next = (msg_end = i) + 1; break; }
                                    else if (queue[i] == '\r' && (next_char = i + 1) < queue.LongLength && queue[next_char] == '\n') { msg_next = (msg_end = i) + 2; break; }
                                }
                                if (msg_end < 0)
                                {
                                    // Message is incomplete. We need more data.
                                    break;
                                }

                                if (msg_end - offset == 3 && Encoding.ASCII.GetString(queue.SubArray(offset, 3)) == "END")
                                {
                                    // Multi-line response end.
                                    lock (_commands) _commands.Dequeue();
                                    cmd_multiline.Finished.Set();
                                }
                                else
                                {
                                    // One line of multi-line response.
                                    cmd_multiline.ProcessData(queue.SubArray(offset, msg_end - offset), event_sink);
                                }

                                offset = msg_next;
                            }
                            else if (cmd is SingleCommand cmd_single)
                            {
                                // Find LF (or CR-LF).
                                long id_end = -1, data_start = -1, msg_end = -1, msg_next = -1;
                                for (long i = offset; i < queue.LongLength; i++)
                                {
                                    long next_char;
                                    if (id_end < 0 && queue[i] == ':') { data_start = (id_end = i) + 1; }
                                    else if (queue[i] == '\n') { msg_next = (msg_end = i) + 1; break; }
                                    else if (queue[i] == '\r' && (next_char = i + 1) < queue.LongLength && queue[next_char] == '\n') { msg_next = (msg_end = i) + 2; break; }
                                }
                                if (msg_end < 0)
                                {
                                    // Message is incomplete. We need more data.
                                    break;
                                }

                                if (id_end >= 0 && id_end - offset == 7 && Encoding.ASCII.GetString(queue.SubArray(offset, 7)) == "SUCCESS")
                                {
                                    // Success response.
                                    lock (_commands) _commands.Dequeue();
                                    cmd_single.Success = true;
                                    cmd_single.Response = Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start)).Trim();
                                    cmd_single.Finished.Set();

                                    // TODO: Send "password" command.
                                }
                                else if (id_end >= 0 && id_end - offset == 5 && Encoding.ASCII.GetString(queue.SubArray(offset, 5)) == "ERROR")
                                {
                                    // Error response.
                                    lock (_commands) _commands.Dequeue();
                                    cmd_single.Success = false;
                                    cmd_single.Response = Encoding.UTF8.GetString(queue.SubArray(data_start, msg_end - data_start)).Trim();
                                    cmd_single.Finished.Set();

                                    // TODO: Send "username" and "password" commands.
                                }

                                offset = msg_next;
                            }
                            else if (offset + 15 <= queue.LongLength && Encoding.ASCII.GetString(queue.SubArray(offset, 15)) == "ENTER PASSWORD:")
                            {
                                // Set authentication requested flag.
                                auth_req.Set();

                                // Consume all queued data past the password prompt.
                                offset = queue.LongLength;
                            }
                        }

                        if (offset > 0)
                        {
                            // Remove processed data from the queue.
                            queue = queue.SubArray(offset);
                        }
                    }
                }));
            _monitor.Start();

            // Wait until openvpn.exe sends authentication request.
            if (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, auth_req }) == 0)
                throw new OperationCanceledException();

            // Send the password.
            ExecuteCommand(password, new SingleCommand(), ct);
        }

        /// <summary>
        /// Set up automatic notification of bandwidth usage once every <paramref name="n"/> seconds; or turn it off
        /// </summary>
        /// <param name="n">Period (in seconds); <c>0</c> to turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SetByteCount(int n, CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand(String.Format("bytecount {0:D}", n), new SingleCommand(), ct);
        }

        /// <summary>
        /// Turn on or off real-time notification of echo messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableEcho(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand(enable ? "echo on" : "echo off", new SingleCommand(), ct);
        }

        /// <summary>
        /// Print the current echo history list
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayEcho(CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand("echo all", new EchoCommand(), ct);
        }

        /// <summary>
        /// Atomically enable real-time notification, plus show any messages in history buffer
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableEcho(CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand("echo on all", new SingleCommand(), new EchoCommand(), ct);
        }

        /// <summary>
        /// Return current hold flag
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns><c>true</c> if hold flag is set; <c>false</c> otherwise</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "hold="</exception>
        public bool GetHold(CancellationToken ct = default(CancellationToken))
        {
            var result = ExecuteCommand("hold", new SingleCommand(), ct);
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
            return ExecuteCommand(enable ? "hold on" : "hold off", new SingleCommand(), ct);
        }

        /// <summary>
        /// Leave hold state and start OpenVPN, but do not alter the current hold flag setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReleaseHold(CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand("hold release", new SingleCommand(), ct);
        }

        /// <summary>
        /// Enable/disable real-time output of log messages
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableLog(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand(enable ? "log on" : "log off", new SingleCommand(), ct);
        }

        /// <summary>
        /// Show the most recent <paramref name="n"/> lines of log file history
        /// </summary>
        /// <param name="n">Number of lines</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(int n, CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand(String.Format("log {0:D}", n), new LogCommand(), ct);
        }

        /// <summary>
        /// Show currently cached log file history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayLog(CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand("log all", new LogCommand(), ct);
        }

        /// <summary>
        /// Atomically show all currently cached log file history then enable real-time notification of new log file messages
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableLog(CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand("log on all", new SingleCommand(), new LogCommand(), ct);
        }

        /// <summary>
        /// Show the current mute setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Mute setting</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "mute="</exception>
        public int GetMute(CancellationToken ct = default(CancellationToken))
        {
            var result = ExecuteCommand("mute", new SingleCommand(), ct);
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
            return ExecuteCommand(String.Format("mute {0:D}", n), new SingleCommand(), ct);
        }

        /// <summary>
        /// Shows the process ID of the current OpenVPN process
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>openvpn.exe process ID</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "pid="</exception>
        public int GetProcessID(CancellationToken ct = default(CancellationToken))
        {
            var result = ExecuteCommand("pid", new SingleCommand(), ct);
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
            return ExecuteCommand("forget-passwords", new SingleCommand(), ct);
        }

        /// <summary>
        /// Send a <paramref name="signal"/> signal to daemon
        /// </summary>
        /// <param name="signal">Signal to send</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string SendSignal(SignalType signal, CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand(String.Format("signal {0}", Enum.GetName(typeof(SignalType), signal)), new SingleCommand(), ct);
        }

        /// <summary>
        /// Print current OpenVPN state
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayCurrentState(CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand("state", new StateCommand(), ct);
        }

        /// <summary>
        /// Enable/disable real-time notification of state changes
        /// </summary>
        /// <param name="enable"><c>true</c> turn on; <c>false</c> turn off</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string EnableState(bool enable, CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand(enable ? "state on" : "state off", new SingleCommand(), ct);
        }

        /// <summary>
        /// Print current state history
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand("state all", new StateCommand(), ct);
        }

        /// <summary>
        /// Print the <paramref name="n"/> most recent state transitions
        /// </summary>
        /// <param name="n">Number of states</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public void ReplayState(int n, CancellationToken ct = default(CancellationToken))
        {
            ExecuteCommand(String.Format("state {0:D}", n), new StateCommand(), ct);
        }

        /// <summary>
        /// Atomically show state history while at the same time enable real-time state notification of future state transitions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        public string ReplayAndEnableState(CancellationToken ct = default(CancellationToken))
        {
            return ExecuteCommand("state on all", new SingleCommand(), new StateCommand(), ct);
        }

        /// <summary>
        /// Show the current verb setting
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Verbosity level</returns>
        /// <exception cref="UnexpectedReplyException">Response is not "verb="</exception>
        public int GetVerbosity(CancellationToken ct = default(CancellationToken))
        {
            var result = ExecuteCommand("verb", new SingleCommand(), ct);
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
            return ExecuteCommand(String.Format("verb {0:D}", n), new SingleCommand(), ct);
        }

        /// <summary>
        /// Show the current OpenVPN and Management Interface versions
        /// </summary>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Dictionary of versions</returns>
        public Dictionary<string, string> GetVersion(CancellationToken ct = default(CancellationToken))
        {
            var cmd = new VersionCommand();
            ExecuteCommand("version", cmd, ct);
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
            return ExecuteCommand(String.Format("auth-retry {0}", auth_retry.GetParameterValue()), new SingleCommand(), ct);
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console and wait for its result
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string ExecuteCommand(string cmd, SingleCommand cmd_result, CancellationToken ct = default(CancellationToken))
        {
            SendCommand(cmd, cmd_result, ct);

            // Await for the command to finish.
            if (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, cmd_result.Finished  }) == 0)
                throw new OperationCanceledException();

            if (cmd_result.Success)
                return cmd_result.Response.ToString();
            else
                throw new CommandException(cmd_result.Response.ToString());
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console and wait for its result
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        private void ExecuteCommand(string cmd, MultilineCommand cmd_result, CancellationToken ct = default(CancellationToken))
        {
            SendCommand(cmd, cmd_result, ct);

            // Await for the command to finish.
            if (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, cmd_result.Finished }) == 0)
                throw new OperationCanceledException();
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console and wait for its result
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result1">First pending command result</param>
        /// <param name="cmd_result2">Second pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Command response</returns>
        /// <exception cref="CommandException">Command failed</exception>
        private string ExecuteCommand(string cmd, SingleCommand cmd_result1, MultilineCommand cmd_result2, CancellationToken ct = default(CancellationToken))
        {
            SendCommand(cmd, new Command[] { cmd_result1, cmd_result2 }, ct);

            // Await for the second command to finish.
            if (WaitHandle.WaitAny(new WaitHandle[] { ct.WaitHandle, cmd_result2.Finished }) == 0)
                throw new OperationCanceledException();

            if (cmd_result1.Success)
                return cmd_result1.Response.ToString();
            else
                throw new CommandException(cmd_result1.Response.ToString());
        }

        /// <summary>
        /// Sends a command to OpenVPN Management console
        /// </summary>
        /// <param name="cmd">Command to send</param>
        /// <param name="cmd_result">Pending command result</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        private void SendCommand(string cmd, Command cmd_result, CancellationToken ct = default(CancellationToken))
        {
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
        private void SendCommand(string cmd, Command[] cmd_result, CancellationToken ct = default(CancellationToken))
        {
            lock (_command_lock)
            {
                lock (_commands)
                    foreach (var res in cmd_result)
                        _commands.Enqueue(res);

                // Send the command.
                var cmd_bin = Encoding.UTF8.GetBytes(cmd + "\n");
                var write_task = _stream.WriteAsync(cmd_bin, 0, cmd_bin.Length, ct);
                try { write_task.Wait(ct); }
                catch (AggregateException ex) { throw ex.InnerException; }
            }
        }

        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                    Stream.Dispose();

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
