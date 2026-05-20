# Adaptive Defensive Scanner — ADS Roadmap

## 1. Projenin kimliği

Adaptive Defensive Scanner (ADS), klasik anlamda “her şeyi yapan scanner” değildir.

ADS’nin temel kimliği şudur:

```text
Technical finding → Security meaning → Defensive action

Yani:

Teknik bulgu → Güvenlik anlamı → Savunma aksiyonu
```

ADS’nin amacı sadece açık portları veya zafiyetleri listelemek değildir. Asıl amaç, farklı güvenlik araçlarından gelen teknik çıktıları alıp bunları savunma açısından anlamlandırmak, risklendirmek, önceliklendirmek ve aksiyon önerisine dönüştürmektir.

Kısa tanım:
`ADS is a defensive reasoning and action engine.`

Daha açık tanım:
ADS, Nmap / Osmedeus / Nuclei / Tsunami / Amass gibi araçlardan gelen teknik bulguları normalize edip, risk, priority, fix, firewall rule ve rapor çıktısına dönüştüren savunma odaklı analiz motorudur.

## 2. Ana pipeline
ADS’nin temel çalışma akışı:

Input → Scan / Import → Normalize Finding → Service Classification → CVE Enrichment → Context-Aware Risk Analysis → Confidence / Evidence → Priority Engine → Fix Recommendation → Firewall Rule Suggestion → HTML / JSON Report → History / Diff

## 3. Şu an tamamlanan ana yetenekler
Nmap tabanlı aktif tarama, Mock scan, Subnet scanning, Parallel scanning, Host-aware output, Service classification, Context-aware risk scoring, CVE enrichment, Confidence scoring, Evidence engine, Priority engine, Fix recommendation, Firewall rule suggestion, HTML report, JSON report, Scan history, History terminal UX, Cross-platform path normalize, Scan diff, Host-aware diff, Diff terminal UX.

## 4. Yeni açılan integration layer
ADS’ye integrations/ katmanı eklendi. Amacı, başka güvenlik araçlarının çıktılarını ADS’nin normalize veri modeline çevirmektir.

## 5. Nmap XML importer
İlk integration layer adımı olarak Nmap XML importer eklendi. Sadece open portlar ADS pipeline’a alınır.

## 6. Import source metadata
Import edilen bulgularda kaynak bilgisi tutulur (source_tool, source_file).

## 7. Testler
Tüm testler (test_subnet_expand.py, vb.) başarılı.

## 8. Tool Output Interpretation Layer
Bu, ADS’nin gelecek ana geliştirme hattıdır. ADS bu araçların rakibi olmayacak. Onların çıktısını defensive action’a çevirecek.

## 9. Gelecek importer adayları

### 9.1 Nmap XML Importer
Durum: Tamamlandı. Nmap XML çıktısını ScanFinding listesine çevirir.

### 9.2 Osmedeus / httpx JSONL Importer

Durum:
```text
İlk versiyon tamamlandı.
```

İlk sürümde httpx veya Osmedeus içinden gelen HTTP fingerprint JSONL çıktıları okunup ADS’nin ScanFinding modeline çevrilebilir hale getirildi.
Yeni kullanım:
`python main.py --import-httpx-jsonl test_data/httpx_import_test.jsonl --environment external --criticality medium --json`

Importer şu alanları okumaya çalışır:
* url
* host
* port
* scheme
* status-code / status_code / status
* title
* webserver / server
* tech / technologies

İlk versiyonda normalize edilen temel bilgiler:
* host, port, protocol, service, product, version

Örnek httpx JSONL kaydı:
```json
{"url":"[http://admin.example.com:8080](http://admin.example.com:8080)","status_code":200,"title":"Admin Login","webserver":"Apache/2.4.49","tech":["Apache HTTP Server"]}
```

ADS bu kaydı şu şekilde yorumlayabilir:
* admin.example.com
* port: 8080/tcp
* service: http
* product: Apache
* version: 2.4.49

Bu bilgi mevcut ADS pipeline’ına girer:
httpx JSONL → ScanFinding → Service Classification → CVE Enrichment → Risk / Priority → Fix / Firewall Rule / Report

Örnek başarılı sonuç:
```text
admin.example.com Port 8080 http
Product: Apache
Version: 2.4.49
CVE: CVE-2021-41773, CVE-2021-42013
Risk: HIGH
Priority: CRITICAL
```

Bu örnek ADS’nin ana amacını doğrular:
`httpx fingerprint → product/version → CVE enrichment → defensive action`

Eklenen dosyalar:
* integrations/osmedeus_httpx_importer.py
* test_httpx_jsonl_importer.py

main.py içine eklenen argüman:
`--import-httpx-jsonl`

History / JSON / HTML tarafında kullanılan metadata:
```json
{
  "scan_mode": "httpx_jsonl_import",
  "source_tool": "httpx",
  "source_file": "test_data/httpx_import_test.jsonl"
}
```

Şu anki sınırlama:
httpx importer title, status_code ve tech gibi web fingerprint bilgilerini okuyor; ancak ScanFinding modeli şu anda bunları detaylı şekilde rapora taşımıyor.

Bir sonraki mimari karar:
Web fingerprint verilerini kaybetmemek için ScanFinding içine metadata alanı mı eklenecek, yoksa WebFinding / ImportedFinding gibi yeni model mi oluşturulacak?

### 9.3 Nuclei JSON Importer
Durum: Planlandı.

### 9.4 Tsunami JSON Importer
Durum: Planlandı.

### 9.5 Amass / Subfinder Asset Importer
Durum: Planlandı.

### 9.6 Nuclei + httpx correlation
Durum: İleri plan.

## 10. Detector layer
Importer katmanından sonra detector layer eklenebilir. Normalize edilmiş bulgulardan savunma açısından anlamlı olaylar çıkarmak içindir.