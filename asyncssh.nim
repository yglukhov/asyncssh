import libssh2

import strutils, asyncdispatch, net, times
import posix except Time

type
  AuthType = enum
    authPasswd
    authPubkey
    authPubkeyFile

  SSHSession* = ref object of RootObj
    sock: AsyncFD
    sess: Session
    host: string
    port: Port
    username: string
    case auth: AuthType
    of authPasswd:
      password: string
    of authPubkey:
      pk: bool # TODO
    of authPubkeyFile:
      pubKeyFile: string
      privKeyFile: string
      passphrase: string

  SSHProxiedSession* = ref object of SSHSession
    proxyChannel: SSHChannel

  SSHChannel* = ref object
    session: SSHSession
    chan: Channel

var sshInited = false

proc checkError(err: cint) =
  if err != 0:
    raise newException(Exception, "ssh error: " & $err)

proc isAlive*(s: SSHSession): bool = not s.sess.isNil

proc proxySend(alwaysInvalidSock: AsyncFD, buffer: pointer, len: csize, flags: cint, abstract: ptr pointer): csize {.cdecl.} =
  let s = cast[SSHProxiedSession](abstract[])
  result = s.proxyChannel.chan.channel_write(cast[cstring](buffer), len)

proc proxyRecv(alwaysInvalidSock: AsyncFD, buffer: pointer, len: csize, flags: cint, abstract: ptr pointer): csize {.cdecl.} =
  let s = cast[SSHProxiedSession](abstract[])
  result = s.proxyChannel.chan.channel_read(buffer, len)
  if result == LIBSSH2_ERROR_EAGAIN:
    result = -EAGAIN

proc disconnectfunc(s: Session, reason: cint, message: cstring, message_len: cint, language: cstring, language_len: cint, abstract: ptr[pointer]) {.cdecl.} =
  let sess = cast[SSHSession](abstract[])
  sess.sess = nil

proc newProxyChannel(s: SSHSession, host: string, port: Port): Future[SSHChannel] {.async.} =
  result = SSHChannel(session: s)
  while result.chan.isNil:
    result.chan = s.sess.channel_direct_tcpip(host, int(port))
    if not result.chan.isNil:
      break
    let rc = session_last_errno(s.sess)
    if rc == LIBSSH2_ERROR_EAGAIN:
      await sleepAsync(50)
    else:
      raise newException(Exception, "channel_direct_tcpip error: " & $rc)

proc handshake(s: SSHSession): Future[void] {.async.} =
  while true:
    let rc = s.sess.sessionHandshake(s.sock.SocketHandle)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      return
    await sleepAsync(50)

proc userauthPasswordAsync(s: SSHSession, cb: passwd_changereq_func): Future[void] {.async.} =
  while true:
    let rc = s.sess.userauthPassword(s.username, s.password, cb)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      return
    await sleepAsync(50)

proc userauthPubkeyFileAsync(s: SSHSession): Future[void] {.async.} =
  while true:
    let rc = s.sess.userauthPublickeyFromFile(s.username, s.pubkeyFile,
      s.privkeyFile, s.passphrase)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      return
    await sleepAsync(50)

proc recreateSession(s: SSHSession) {.async.} =
  let isProxied = s of SSHProxiedSession
  if not isProxied:
    s.sock = createAsyncNativeSocket()
    await s.sock.connect(s.host, s.port)
  s.sess = sessionInit()
  s.sess.sessionSetBlocking(0)
  s.sess.session_abstract()[] = cast[pointer](s)
  s.sess.session_callback_set(LIBSSH2_CALLBACK_DISCONNECT, cast[pointer](disconnectfunc))

  if isProxied:
    s.sess.session_callback_set(LIBSSH2_CALLBACK_SEND, cast[pointer](proxySend))
    s.sess.session_callback_set(LIBSSH2_CALLBACK_RECV, cast[pointer](proxyRecv))

  await s.handshake()
  case s.auth
  of authPasswd:
    await s.userauthPasswordAsync(nil)
  of authPubkey:
    doASsert(false)
  of authPubkeyFile:
    await s.userauthPubkeyFileAsync()

proc restoreIfNeeded*(s: SSHSession) {.async.} =
  if s of SSHProxiedSession:
    let s = SSHProxiedSession(s)
    let ps = s.proxyChannel.session
    await ps.restoreIfNeeded()
    s.proxyChannel = await ps.newProxyChannel(s.host, s.port)
  if not s.isAlive:
    await s.recreateSession()

template initSSHIfNeeded() =
  if not sshInited:
    init(0).checkError()

proc newSSHSession*(host: string, port: Port, username, password: string): Future[SSHSession] {.async.} =
  initSSHIfNeeded()

  result = SSHSession(
    host: host, port: port,
    auth: authPasswd,
    username: username,
    password: password
    )
  await result.restoreIfNeeded()

proc newSSHSession*(host: string, port: Port, username, pubKeyFile, privKeyFile: string, passphrase: string = ""): Future[SSHSession] {.async.} =
  initSSHIfNeeded()
  result = SSHSession(
    host: host, port: port,
    auth: authPubkeyFile,
    username: username,
    pubKeyFile: pubKeyFile,
    privKeyFile: privKeyFile,
    passphrase: passphrase
    )
  await result.restoreIfNeeded()


proc newProxiedSSHSession*(proxySession: SSHSession, host: string, port: Port, username, password: string): Future[SSHProxiedSession] {.async.} =
  result = SSHProxiedSession(
    host: host, port: port,
    auth: authPasswd,
    username: username,
    password: password
    )

  result.proxyChannel = await proxySession.newProxyChannel(host, port)
  await result.restoreIfNeeded()

proc shutdown*(s: SSHSession) =
  discard s.sess.sessionDisconnect("Normal shutdown, thank you for playing")
  discard s.sess.sessionFree()
  discard s.sock.SocketHandle.close()
  # libssh2.exit()
  # quit()

proc waitsocket(s: SSHSession): Future[void] =
  if s of SSHProxiedSession:
    result = waitsocket(SSHProxiedSession(s).proxyChannel.session)
  else:
    result = newFuture[void]("waitsocket")
    let f = result
    let dir = s.sess.sessionBlockDirections()

    if (dir and LIBSSH2_SESSION_BLOCK_INBOUND) == LIBSSH2_SESSION_BLOCK_INBOUND:
      addRead(s.sock) do(fd: AsyncFD) -> bool:
        if not f.finished: f.complete()
        return true

    if (dir and LIBSSH2_SESSION_BLOCK_OUTBOUND) == LIBSSH2_SESSION_BLOCK_OUTBOUND:
      addWrite(s.sock) do(fd: AsyncFD) -> bool:
        if not f.finished: f.complete()
        return true

proc readString*(c: SSHChannel): Future[string] {.async.} =
  var buffer: array[0..1024, char]
  var res = ""
  while true:
    let rc = c.chan.channelRead(addr buffer, buffer.len)
    if rc > 0:
      for i in 0 ..< rc:
        res.add(buffer[i])
    elif rc == LIBSSH2_ERROR_EAGAIN:
      await waitsocket(c.session)
    else:
      checkError(rc)
      break
  return res

proc openSessionChannel(s: SSHSession): Future[SSHChannel] {.async.} =
  result = SSHChannel()
  while true:
    result.chan = s.sess.channelOpenSession()
    if result.chan.isNil and s.sess.sessionLastErrno() == LIBSSH2_ERROR_EAGAIN:
      await waitsocket(s)
    else:
      break
  if result.chan.isNil:
    checkError(s.sess.sessionLastErrno())
    result = nil
  else:
    result.session = s

proc exec(channel: SSHChannel, command: string): Future[void] {.async.} =
  while true:
    let rc = channel.chan.channelExec(command)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      return
    await waitsocket(channel.session)

proc close*(channel: SSHChannel): Future[void] {.async.} =
  while true:
    let rc = channel.chan.channelClose()
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      return
    await waitsocket(channel.session)

proc free*(channel: SSHChannel): cint =
  channel.chan.channelFree()

proc disposeChannelAsync(ch: SSHChannel) {.async.} =
  await ch.close()
  discard ch.free()

proc exec*(s: SSHSession, command: string): Future[tuple[output: string, exitCode: int]] {.async.} =
  let ch = await s.openSessionChannel()
  await ch.exec(command)
  result.output = await ch.readString()
  result.exitCode = ch.chan.channelGetExitStatus()
  asyncCheck disposeChannelAsync(ch)

proc scpRecv(s: SSHSession, path: string): Future[tuple[c: SSHChannel, s: Stat]] {.async.} =
  result.c = SSHChannel()
  while result.c.chan.isNil:
    result.c.chan = s.sess.scp_recv(path, addr result.s)
    if not result.c.chan.isNil:
      break
    let rc = session_last_errno(s.sess)
    if rc == LIBSSH2_ERROR_EAGAIN:
      await waitsocket(s)
    elif rc == LIBSSH2_ERROR_SCP_PROTOCOL:
      # File not found. Return nil
      result.c = nil
      break
    else:
      raise newException(Exception, "scp_recv error: " & $rc)

proc lastError(s: Session): string =
  var buf: cstring
  discard session_last_error(s, addr buf, nil, 0)
  $buf

proc scpSend(s: SSHSession, path: string, size: uint64, mode: cint, mtime, atime: DateTime): Future[SSHChannel] {.async.} =
  result = SSHChannel()
  let mtime = posix.Time(mtime.toTime.toUnix)
  let atime = posix.Time(atime.toTime.toUnix)
  while result.chan.isNil:
    result.chan = s.sess.scp_send64(path, cint(mode), size, mtime, atime)
    if not result.chan.isNil:
      break
    let rc = session_last_errno(s.sess)
    if rc == LIBSSH2_ERROR_EAGAIN:
        await waitsocket(s)
    else:
      raise newException(Exception, "scp_send64 error: " & $rc & ": " & lastError(s.sess))

proc getFile*(s: SSHSession, path: string): Future[string] {.async.} =
  let r = await s.scpRecv(path)
  if r.c.isNil: return
  result = ""

  var got = 0
  var buf = newString(1024)
  while got < r.s.st_size:
    buf.setLen(1024)
    var amount = 1024

    if r.s.st_size - got < amount:
      amount = int(r.s.st_size - got)

    let rc = channel_read(r.c.chan, addr buf[0], amount)

    if rc > 0:
      buf.setLen(rc)
      result &= buf
      got += rc
    elif rc < 0:
      if rc == LIBSSH2_ERROR_EAGAIN:
        await waitsocket(s)
      else:
        checkError(rc)
        break
  discard r.c.free()

proc putFile*(s: SSHSession, path: string, mode: int, mtime, atime: DateTime, content: string) {.async.} =
  let sz = content.len
  let ch = await s.scpSend(path, uint64(sz), cint(mode), mtime, atime)
  var sent = 0
  while sent < sz:
    let rc = channel_write(ch.chan, unsafeAddr content[sent], sz - sent)
    if rc > 0:
      sent += rc
    elif rc < 0:
      if rc == LIBSSH2_ERROR_EAGAIN:
        await waitsocket(s)
      else:
        checkError(rc)
        break

  while true:
    let rc = channel_send_eof(ch.chan)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      break
    await waitsocket(s)

  while true:
    let rc = channel_wait_eof(ch.chan)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      break
    await waitsocket(s)

  while true:
    let rc = channel_wait_closed(ch.chan)
    if rc != LIBSSH2_ERROR_EAGAIN:
      checkError(rc)
      break
    await waitsocket(s)

  discard ch.free()
