# AdiosDPI

[English](README.md) · Türkçe

Bu yazılım, birçok internet servis sağlayıcısında bulunan ve belirli sitelere erişimi engelleyen Derin Paket İnceleme sistemlerini atlatmak için tasarlanmıştır.

Optik ayırıcı ya da port yansıtma ile bağlanan, hiçbir veriyi engellemeyip yalnızca istenen hedeften daha hızlı yanıt veren DPI'ı (**Pasif DPI**) ve sıralı bağlanan **Aktif DPI**'ı işler. VPN değildir.

**Windows** ve yönetici yetkisi gerekir.

# Hızlı başlangıç

Zip'i açın, `adiosdpi.exe` dosyasını yönetici olarak çalıştırın ve BAŞLAT'a basın. Otomatik modda, test siteniz (`discord.com` ya da yazdığınız site) açılana kadar ayarları dener, işe yarayanı çalıştırır. "Servis olarak kur" programı Windows ile başlatır.

Pencere, Windows'un diline (Türkçe ya da İngilizce) ve temasına uyar.

Türkiye'de birçok engel, Discord dahil, yalnızca DNS zehirlemesidir. O zaman `dns` hazır ayarı yeter (Quad9'a düz DNS, yedek olarak OpenDNS). Otomatik mod hangisi olduğunu söyler.

# Komut satırı

```
adiosdpi.exe --preset dns             hazır ayarlar: dns, dns-5, dns-9, dns-ttl5, dns-ttl3, ttl3
adiosdpi.exe --probe discord.com      bir siteyi açan ayarı bulur
adiosdpi.exe --dns-check discord.com  sistem DNS'i, düz DNS ve DNS over HTTPS cevaplarını karşılaştırır
adiosdpi.exe --install --preset dns   servis olarak çalıştırır (--remove, --status)
adiosdpi.exe -h                       tüm seçenekler
```

Başka DNS sunucusu için `--dns-addr`, `--dns-port` ve `--dns-backup`. `--blacklist <dosya>` hileleri yalnızca listedeki sitelere uygular (`lists/blocked-tr.txt` bir başlangıçtır). İlk paketi istediğiniz yerden kesmek için `--split-pos 1,midsld,sniext+1` (ayrıca `host`, `endhost`, `sld`, `endsld`, `-N`). `--seqovl N` ilk parçayı N bayt erken başlatır, `--md5sig` yanlış TCP MD5 imzalı bir sahte paket daha gönderir. Pencere uygulaması olduğu için terminalde komut istemi, çıktı yazılmadan önce geri döner.

Kipler:

| Kip | Seçenekler |
|---|---|
| `-5` | `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload` |
| `-6` | `-f 2 -e 2 --wrong-seq --reverse-frag --max-payload` |
| `-7` | `-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload` |
| `-8` | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload` |
| `-9` (varsayılan) | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q` |

# Notlar

- Bazı antivirüs programları WinDivert sürücüsünü işaretler. Klasör için istisna ekleyin.
- Program kod imzalı değildir, Windows "bilinmeyen yayıncı" der.
- Aynı anda tek bir paket aracı çalıştırın.

# Nasıl çalışır

**Pasif DPI** genellikle hedef siteden daha hızlı bir HTTP 302 yönlendirmesi (HTTP) ya da TCP Reset (HTTPS) gönderir. Paketlerinin IP Identification alanı çoğunlukla `0x0000` veya `0x0001`'dir ve düşürülür (`-p`).

**Aktif DPI**, ilk veri paketinin TCP düzeyinde parçalanması, `Host` başlığı değişiklikleri ve düşük Time-To-Live, yanlış sağlama toplamı ya da yanlış TCP Sequence/Acknowledgement numaraları taşıyan sahte HTTP/HTTPS paketleriyle kandırılır; böylece DPI veriyi sınıflandıramaz.

Program, paketleri kullanıcı alanına yönlendiren [WinDivert](https://github.com/basil00/WinDivert) sürücüsünü yükler. Penceresi açık olduğu sürece ya da bir Windows hizmeti olarak çalışır.

# Kaynaktan derleme

GNU Make, [mingw-w64](https://www.mingw-w64.org) ve [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) gerekir. `src/` içinde:

`make BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x64`

Linux'ta `CPREFIX=x86_64-w64-mingw32-` ekleyin. x86 için `BIT64=1`'i kaldırın ve `.../x86` kullanın.

# Teşekkürler

- [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI): temel alınan proje.
- [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey): Türkiye hazır ayarları (`ttl3`, `dns-ttl3`, `dns-ttl5`) bu çatalın profillerini izler.
- [basil00/WinDivert](https://github.com/basil00/WinDivert): paket yakalama ve gönderme için kullanılan sürücü.

Diğer atıflar [NOTICE](NOTICE) dosyasında.
