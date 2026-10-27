# cchat

Chat server and client made in C.

## Connecting

When the client starts it shows the saved servers and these options:

* Type the number of a saved server to connect to it.
* `a` adds a new server: enter `IP:PORT` and the encryption key.  The key is
  saved in `~/.cchat/IP:PORT` with mode `0600`, so the server appears in the
  list next time.
* `b` opens a direct connection: enter `IP:PORT` and the key.  These details
  are not saved.
* `q` quits.

The username and password are requested after a server has been selected.
Saved servers are discovered from the key files in `~/.cchat/`; non-address
files and directories (such as `Downloads`) are ignored.

## Chat

The chat fills the terminal and keeps the prompt on the bottom line.

* `Up` / `Down` scroll through the loaded history one line at a time.
* `PageUp` / `PageDown` scroll a full page.
* When you are scrolled up, the prompt shows how many lines back you are.
  New messages keep the view in place; scroll back down to follow the chat.
* `Enter` sends the message, `Ctrl-U` clears the input, and `Ctrl-L` redraws
  the screen.
* `Ctrl-C` quits. The client keeps the most recent 5000 chat lines in memory.

Every 20 seconds the client sends a small `@PING` heartbeat to the server,
which answers with `@PONG`.  This keeps idle connections from being dropped
by NAT or firewalls.  Heartbeats never appear in the chat and are not saved to
history.  There is no idle timeout: an inactive user stays connected
indefinitely.

## File transfers

The client can send files to the chat and download them again later.

* Press `Ctrl-O` or type `/upload` to open the built-in file picker.
  Files are transferred in chunks; the per-file limit comes from the server
  (`filesize.conf`, 16 MiB by default).
  * `j`/`k` or the arrow keys move the cursor.
  * `h`/`l` or the left/right arrow keys change directory.
  * `Space` selects or deselects a file.
  * `Enter` sends the selected files (or the file under the cursor when
    nothing is selected).
  * `q` or `Esc` cancels.
* Press `Ctrl-F` or type `/files` to open the server file list.  The list
  contains the files currently stored on the server.
  * `j`/`k` or the arrow keys move the cursor.
  * `Space` selects files, `Enter` downloads them, `q`/`Esc` closes the list.
* Downloaded files are stored in `~/.cchat/Downloads`.
* Type `/help` in the chat to show the command list.
* If you only need one file, type `/get <id>` (for example `/get 12`) to
  download it directly by its number.

Uploaded files are announced in the chat with a server-assigned file number.
The server keeps them in `files/` next to its configuration files; the
`files.index` file maps file numbers to names.

## Server configuration

`filesize.conf` controls the maximum upload size.  The four values are added
together:

```
kb = 0
mb = 16
gb = 0
tb = 0
```

The example above means 16 MiB.  For example, `mb = 16` and `kb = 512` gives
16.5 MiB.  The server sends the resulting limit to clients automatically.
Setting every unit to `0` disables non-empty uploads.

`history.conf` controls how many chat lines are kept (`0` = unlimited).  When
a non-zero limit is used and a file announcement falls out of the history, the
server also deletes that file from `files/` and removes it from `files.index`.
With the default `history.conf` value (`0`), files are kept indefinitely.
