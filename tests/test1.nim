import asyncssh
import asyncdispatch, times

from os import expandTilde

let
  localSshPubKey = expandTilde("~/.ssh/id_rsa.pub")
  localSshPrivKey = expandTilde("~/.ssh/id_rsa")

proc main() {.async.} =
  # Login with username/password. Alternative methods are available.
  let s = await newSSHSession("127.0.0.1", Port(22), "root",
      localSshPubKey, localSshPrivKey)
  # Put file
  await s.putFile(path = "hello.txt", mode = 0o666,
                  mtime = now(), atime = now(),
                  content = "Hello world!")
  # # Get file
  let content = await s.getFile(path = "hello.txt")
  assert(content == "Hello world!")

  # Execute commands
  let (output, retCode) = await s.exec("uname")
  assert(retCode == 0)
  echo "Uname is: ", output

  # Close connection
  s.shutdown()

waitFor main()
