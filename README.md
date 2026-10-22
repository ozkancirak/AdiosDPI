# AdiosDPI

English · [Türkçe](README.tr.md)

This software is designed to bypass Deep Packet Inspection systems found in many Internet Service Providers which block access to certain websites.

It handles DPI connected using optical splitter or port mirroring (**Passive DPI**) which do not block any data but just reply faster than the requested destination, and **Active DPI** connected in sequence. It is not a VPN.

**Windows** with administrator privileges required.

# Quick start

1. [Build](#how-to-build-from-source) `adiosdpi.exe` and put it in one folder with `WinDivert.dll` and `WinDivert64.sys` from the WinDivert download.
2. Run `adiosdpi.exe` as administrator, without any options. If it works — congratulations! You can use it as-is or configure further.
3. If your provider intercepts DNS requests, use the `--dns-addr` option with a public DNS resolver running on a non-standard port, for example Yandex DNS: `adiosdpi.exe --dns-addr 77.88.8.8 --dns-port 1253`.

# Options

Run `adiosdpi.exe -h` for all options. Modes:

| Mode | Options |
|---|---|
| `-5` | `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload` |
| `-6` | `-f 2 -e 2 --wrong-seq --reverse-frag --max-payload` |
| `-7` | `-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload` |
| `-8` | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload` |
| `-9` (default) | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q` |

# How does it work

**Passive DPI** usually sends an HTTP 302 Redirect (HTTP) or a TCP Reset (HTTPS) faster than the destination website. Its packets usually have the IP Identification field equal to `0x0000` or `0x0001` and are dropped (`-p`).

**Active DPI** is fooled with TCP-level fragmentation of the first data packet, `Host` header tricks, and fake HTTP/HTTPS packets with a low Time-To-Live, an incorrect checksum or incorrect TCP Sequence/Acknowledgement numbers, so the DPI cannot classify the data.

The program loads the [WinDivert](https://github.com/basil00/WinDivert) driver, which redirects packets to user space. It runs as long as the console window is open, or as a Windows service.

# How to build from source

You need GNU Make, [mingw-w64](https://www.mingw-w64.org) and [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2). In `src/`:

`make BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x64`

On Linux add `CPREFIX=x86_64-w64-mingw32-`. For x86 drop `BIT64=1` and use `.../x86`.

# Thanks

- [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI): the project this is based on.
- [basil00/WinDivert](https://github.com/basil00/WinDivert): the driver used for packet capture and injection.

More credits in [NOTICE](NOTICE).
