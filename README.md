# AdiosDPI

English · [Türkçe](README.tr.md)

This software is designed to bypass Deep Packet Inspection systems found in many Internet Service Providers which block access to certain websites.

It handles DPI connected using optical splitter or port mirroring (**Passive DPI**) which do not block any data but just reply faster than the requested destination, and **Active DPI** connected in sequence. It is not a VPN.

**Windows** with administrator privileges required.

# Quick start

Unzip, run `adiosdpi.exe` as administrator and press START. In Automatic mode it tries settings until your test site opens (`discord.com`, or whatever you type), then runs the one that worked. "Install as a service" makes it start with Windows.

The window follows your Windows language (Turkish or English) and theme.

In Turkey many blocks, Discord included, are only DNS poisoning. The `dns` preset (plain DNS to Quad9, OpenDNS as backup) is then enough. Automatic mode tells which case you have.

# Command line

```
adiosdpi.exe --preset dns             ready options: dns, dns-5, dns-9, dns-ttl5, dns-ttl3, ttl3
adiosdpi.exe --probe discord.com      find the setting that opens a site
adiosdpi.exe --dns-check discord.com  compare system DNS, plain DNS and DNS over HTTPS
adiosdpi.exe --install --preset dns   run as a service (--remove, --status)
adiosdpi.exe -h                       all options
```

Another DNS server: `--dns-addr`, `--dns-port` and `--dns-backup`. `--blacklist <file>` limits the tricks to the listed sites (`lists/blocked-tr.txt` is a start). Cut the first packet where you choose with `--split-pos 1,midsld,sniext+1` (also `host`, `endhost`, `sld`, `endsld`, `-N`). `--seqovl N` starts the first piece N bytes early, `--md5sig` sends one more fake with a wrong TCP MD5 signature. In a terminal the prompt comes back before the output appears, because this is a window program.

Modes:

| Mode | Options |
|---|---|
| `-5` | `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload` |
| `-6` | `-f 2 -e 2 --wrong-seq --reverse-frag --max-payload` |
| `-7` | `-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload` |
| `-8` | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload` |
| `-9` (default) | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q` |

# Notes

- Some antivirus programs flag the WinDivert driver. Add an exception for the folder.
- The program is not code-signed, so Windows says "unknown publisher".
- Run only one packet tool at a time.

# How does it work

**Passive DPI** usually sends an HTTP 302 Redirect (HTTP) or a TCP Reset (HTTPS) faster than the destination website. Its packets usually have the IP Identification field equal to `0x0000` or `0x0001` and are dropped (`-p`).

**Active DPI** is fooled with TCP-level fragmentation of the first data packet, `Host` header tricks, and fake HTTP/HTTPS packets with a low Time-To-Live, an incorrect checksum or incorrect TCP Sequence/Acknowledgement numbers, so the DPI cannot classify the data.

The program loads the [WinDivert](https://github.com/basil00/WinDivert) driver, which redirects packets to user space. It runs as long as its window is open, or as a Windows service.

# How to build from source

You need GNU Make, [mingw-w64](https://www.mingw-w64.org) and [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2). In `src/`:

`make BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x64`

On Linux add `CPREFIX=x86_64-w64-mingw32-`. For x86 drop `BIT64=1` and use `.../x86`.

# Thanks

- [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI): the project this is based on.
- [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey): the Turkey presets (`ttl3`, `dns-ttl3`, `dns-ttl5`) follow the profiles of this fork.
- [basil00/WinDivert](https://github.com/basil00/WinDivert): the driver used for packet capture and injection.

More credits in [NOTICE](NOTICE).
