# asyncssh
High level async libssh2 wrapper

- Supports tunneling. SSHSessions can be made on top of other SSHSessions.

```nim
import asyncdispatch, asyncssh, times

proc main() {.async.} =
  # Login with username/password. Alternative methods are available.
  let s = await newSSHSession("myhost.local", Port(22), "root", "mySecurePassword")
  # Put file
  await s.putFile(path = "hello.txt", mode = 0666, mtime = now(), atime = now(),
                  content = "Hello world!")
  # Get file
  let content = await s.getFile(path = "hello.txt")
  assert(content == "Hello world!")

  # Execute commands
  let (output, retCode) = await s.exec("uname")
  assert(retCode == 0)
  echo "Uname is: ", output

  # Close connection
  s.shutdown()

waitFor main()
```

