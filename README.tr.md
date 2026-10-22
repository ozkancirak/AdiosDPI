# AdiosDPI

[English](README.md) · Türkçe

Bu yazılım, birçok internet servis sağlayıcısında bulunan ve belirli sitelere erişimi engelleyen Derin Paket İnceleme sistemlerini atlatmak için tasarlanmıştır.

Optik ayırıcı ya da port yansıtma ile bağlanan, hiçbir veriyi engellemeyip yalnızca istenen hedeften daha hızlı yanıt veren DPI'ı (**Pasif DPI**) ve sıralı bağlanan **Aktif DPI**'ı işler. VPN değildir.

**Windows** ve yönetici yetkisi gerekir.

# Hızlı başlangıç

1. `adiosdpi.exe` dosyasını [derleyin](#kaynaktan-derleme) ve WinDivert indirmesindeki `WinDivert.dll` ile `WinDivert64.sys` dosyalarıyla aynı klasöre koyun.
2. `adiosdpi.exe` dosyasını yönetici olarak, hiçbir seçenek vermeden çalıştırın. Çalışırsa tebrikler! Olduğu gibi kullanabilir ya da ayrıca ayarlayabilirsiniz.
3. Servis sağlayıcınız DNS isteklerine müdahale ediyorsa, standart olmayan bir portta çalışan herkese açık bir DNS çözücüyle `--dns-addr` seçeneğini kullanın; örneğin Yandex DNS: `adiosdpi.exe --dns-addr 77.88.8.8 --dns-port 1253`.

# Seçenekler

Tüm seçenekler için `adiosdpi.exe -h` çalıştırın. Kipler:

| Kip | Seçenekler |
|---|---|
| `-5` | `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload` |
| `-6` | `-f 2 -e 2 --wrong-seq --reverse-frag --max-payload` |
| `-7` | `-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload` |
| `-8` | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload` |
| `-9` (varsayılan) | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q` |

# Nasıl çalışır

**Pasif DPI** genellikle hedef siteden daha hızlı bir HTTP 302 yönlendirmesi (HTTP) ya da TCP Reset (HTTPS) gönderir. Paketlerinin IP Identification alanı çoğunlukla `0x0000` veya `0x0001`'dir ve düşürülür (`-p`).

**Aktif DPI**, ilk veri paketinin TCP düzeyinde parçalanması, `Host` başlığı değişiklikleri ve düşük Time-To-Live, yanlış sağlama toplamı ya da yanlış TCP Sequence/Acknowledgement numaraları taşıyan sahte HTTP/HTTPS paketleriyle kandırılır; böylece DPI veriyi sınıflandıramaz.

Program, paketleri kullanıcı alanına yönlendiren [WinDivert](https://github.com/basil00/WinDivert) sürücüsünü yükler. Konsol penceresi açık olduğu sürece ya da bir Windows hizmeti olarak çalışır.

# Kaynaktan derleme

GNU Make, [mingw-w64](https://www.mingw-w64.org) ve [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) gerekir. `src/` içinde:

`make BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x64`

Linux'ta `CPREFIX=x86_64-w64-mingw32-` ekleyin. x86 için `BIT64=1`'i kaldırın ve `.../x86` kullanın.

# Teşekkürler

- [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI): temel alınan proje.
- [basil00/WinDivert](https://github.com/basil00/WinDivert): paket yakalama ve gönderme için kullanılan sürücü.

Diğer atıflar [NOTICE](NOTICE) dosyasında.
