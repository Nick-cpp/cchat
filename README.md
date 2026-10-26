# cchat

Chat server and client made in C.

## Chat

The chat fills the terminal and keeps the prompt on the bottom line.

* `Up` / `Down` scroll through the loaded history one line at a time.
* `PageUp` / `PageDown` scroll a full page.
* When you are scrolled up, the prompt shows how many lines back you are.
  New messages keep the view in place; scroll back down to follow the chat.
* `Enter` sends the message, `Ctrl-U` clears the input, and `Ctrl-L` redraws
  the screen.
* `Ctrl-C` quits. The client keeps the most recent 5000 chat lines in memory.

## File transfers

The client can send files to the chat and download them again later.

* Press `Ctrl-O` or type `/upload` to open the built-in file picker.
  Files are transferred in chunks; the current limit is 16 MiB per file.
  * `j`/`k` or the arrow keys move the cursor.
  * `h`/`l` or the left/right arrow keys change directory.
  * `Space` selects or deselects a file.
  * `Enter` sends the selected files (or the file under the cursor when
    nothing is selected).
  * `q` or `Esc` cancels.
* Press `Ctrl-F` or type `/files` to open the server file list.  The list
  contains every file ever uploaded, so files mentioned in older messages can
  still be downloaded.
  * `j`/`k` or the arrow keys move the cursor.
  * `Space` selects files, `Enter` downloads them, `q`/`Esc` closes the list.
* Downloaded files are stored in `~/.cchat/Downloads`.
* Type `/help` in the chat to show the command list.
* If you only need one file, type `/get <id>` (for example `/get 12`) to
  download it directly by its number.

Uploaded files are announced in the chat with a server-assigned file number.
The server keeps them in `files/` next to its configuration files; the
`files.index` file maps file numbers to names.
