# wtport ⚡
Because sometimes you just wanna know who the f*k stole port 3000.

## 🚀 What is this?
wtport is a cross-platform CLI tool (Windows + Linux + macOS) that helps you find and free ports instantly.
Tired of seeing “Port already in use” while running your dev server?
This little guy hunts down the culprit and — if you ask nicely — kills it. 🪓

## 🧠 Features
- 🔍 wtport → show all listening ports + their owners
- 💀 freeport <PORT> → force kill whatever’s holding that port
- 🧾 wtport version → show the current version
- 💡 wtport help → list all commands

## List Port:
```bash
wtport list -l ollama
```
```
+-------------------------------------------------------------------------------------------+
| 🔥 WTF Is This Port?                                                                      |
+-------+------+-----------------+-----------------+-------------+--------------------------+
| PROTO | TYPE | LOCAL ADDRESS   | FOREIGN ADDRESS | STATE       | PROCESS                  |
+-------+------+-----------------+-----------------+-------------+--------------------------+
| TCP   | IPV4 | 0.0.0.0:11434   | 0.0.0.0:0       | LISTENING   | 9264/ollama.exe@nil      |
| TCP   | IPV4 | 127.0.0.1:3716  | 0.0.0.0:0       | LISTENING   | 17836/ollama.exe@nil     |
| TCP   | IPV4 | 127.0.0.1:3716  | 127.0.0.1:8572  | ESTABLISHED | 17836/ollama.exe@nil     |
| TCP   | IPV4 | 127.0.0.1:8572  | 127.0.0.1:3716  | ESTABLISHED | 9264/ollama.exe@nil      |
| TCP   | IPV4 | 127.0.0.1:13134 | 0.0.0.0:0       | LISTENING   | 24364/ollama app.exe@nil |
| TCP   | IPV6 | :::11434        | :::0            | LISTENING   | 9264/ollama.exe@nil      |
| TCP   | IPV6 | ::1:11434       | ::1:8568        | ESTABLISHED | 9264/ollama.exe@nil      |
+-------+------+-----------------+-----------------+-------------+--------------------------+
```
