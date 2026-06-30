# Thuật toán Quét Virus - ClamAV Signature Reference

> Tài liệu tổng hợp chi tiết về các thuật toán quét virus trong ClamAV, dựa trên tài liệu chính thức tại https://docs.clamav.net/manual/Signatures.html và các trang con.
> Mục đích: Cung cấp nền tảng lý thuyết và thực hành để xây dựng công cụ chống virus tùy chỉnh.

---

## Mục lục

1. [Tổng quan kiến trúc ClamAV](#1-tổng-quan-kiến-trúc-clamav)
2. [Các định dạng Database](#2-các-định-dạng-database)
3. [Hash-based Signatures (.hdb, .hsb, .mdb, .msb, .imp)](#3-hash-based-signatures)
4. [Extended Signatures (.ndb)](#4-extended-signatures-ndb)
5. [Logical Signatures (.ldb)](#5-logical-signatures-ldb)
6. [Container Metadata Signatures (.cdb)](#6-container-metadata-signatures-cdb)
7. [Bytecode Signatures (.cbc)](#7-bytecode-signatures-cbc)
8. [Phishing Signatures (.pdb, .gdb, .wdb)](#8-phishing-signatures-pdb-gdb-wdb)
9. [YARA Rules (.yar, .yara)](#9-yara-rules)
10. [Các công cụ hỗ trợ (sigtool)](#10-các-công-cụ-hỗ-trợ-sigtool)
11. [Quy trình xây dựng công cụ chống virus](#11-quy-trình-xây-dựng-công-cụ-chống-virus)
12. [Ví dụ thực tế - Xây dựng hệ thống quét đơn giản](#12-ví-dụ-thực-tế)

---

## 1. Tổng quan kiến trúc ClamAV

### 1.1. Luồng xử lý file

```
Input File
    │
    ▼
┌─────────────────┐
│ File Type Magic │  ← Xác định loại file qua .ftm (File Type Magic)
│   Detection     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Decompression  │  ← Giải nén ZIP, RAR, 7Z, GZIP, BZIP2, XZ,...
│  & Extraction   │    Tạo file tạm thời trong /tmp
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Normalization  │  ← Chuẩn hóa HTML, JavaScript, ASCII text
│                 │    (lowercase, bỏ whitespace, decode entities)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PE Unpacking   │  ← Giải nén UPX, FSG, Petite, MEW, ASPack,...
│  (if applicable)│    Tạo file PE đã unpack để quét tiếp
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Signature Match │  ← So khớp với các signature database
│   (Aho-Corasick)│    .hdb, .hsb, .ndb, .ldb, .cdb, .cbc, .yar
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │ Alert? │
    └───┬────┘
        │
   Có ◄─┤──► Không ──► OK
        │
        ▼
   FOUND / INFECTED
```

### 1.2. Các thành phần chính

| Thành phần | Mô tả |
|-----------|-------|
| `libclamav` | Thư viện lõi chứa engine quét virus |
| `clamscan` | Công cụ quét dòng lệnh (CLI) |
| `clamd` | Daemon chạy nền, phục vụ quét theo yêu cầu |
| `freshclam` | Cập nhật database tự động |
| `sigtool` | Công cụ tạo và kiểm tra signature |
| `clambc` | Công cụ phân tích bytecode signatures |

### 1.3. CVD/CLD Database Archives

ClamAV phân phối signature qua file CVD (ClamAV Virus Database) - container nén và ký số:

```
CVD Header (512 bytes):
┌─────────────────────────────────────────────────────────┐
│ ClamAV-VDB:build_time:version:num_sigs:min_flevel:MD5:  │
│ digital_signature:builder:build_time_sec                 │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────┐
│  Compressed     │
│  Signature DBs  │  ← main.cvd, daily.cvd, bytecode.cvd
│  (.ndb, .ldb,   │    Giải nén bằng: sigtool --unpack file.cvd
│   .hdb, etc.)   │
└─────────────────┘
```

---

## 2. Các định dạng Database

### 2.1. Settings Databases

| Extension | Mục đích |
|-----------|----------|
| `.cfg` | Dynamic config settings |
| `.cat`, `.crb` | Trusted và revoked PE certificates |
| `.ftm` | File Type Magic - xác định loại file |

### 2.2. Signature Databases

#### Body-based Signatures (so khớp nội dung)

| Extension | Mô tả | File |
|-----------|-------|------|
| `.ndb`, `.ndu` | Extended Signatures | Mỗi dòng = 1 signature |
| `.ldb`, `.ldu` | Logical Signatures | Kết hợp nhiều subsig bằng logic |
| `.idb` | Icon Signatures | Dùng với Logical Signatures |
| `.cdb` | Container Metadata Signatures | So khớp metadata archive |
| `.cbc` | Bytecode Signatures | Plugin C code compiled to bytecode |
| `.pdb`, `.gdb`, `.wdb` | Phishing URL Signatures | Phát hiện phishing |

#### Hash-based Signatures (so khớp hash)

| Extension | Hash Type | Đối tượng |
|-----------|-----------|-----------|
| `.hdb`, `.hdu` | MD5 | Toàn bộ file |
| `.hsb`, `.hsu` | SHA1/SHA256 | Toàn bộ file |
| `.mdb`, `.mdu` | MD5 | PE Section |
| `.msb`, `.msu` | SHA1/SHA256 | PE Section |
| `.imp` | MD5 | PE Import Table |

> **Lưu ý**: File `.ndu`, `.ldu`, `.hdu`, `.hsu`, `.mdu`, `.msu` chỉ được load khi bật PUA (Potentially Unwanted Application) signatures.

### 2.3. Other Database Files

| Extension | Mục đích |
|-----------|----------|
| `.fp`, `.sfp` | False Positive whitelist |
| `.ign`, `.ign2` | Ignore signatures |
| `.pwdb` | Encrypted archive passwords |
| `.info` | Database information |

### 2.4. Quy tắc đặt tên Signature

```
{platform}.{category}.{name}-{signature_id}-{revision}
```

Chỉ được dùng: alphanumeric, dash (`-`), dot (`.`), underscore (`_`).
**KHÔNG** dùng: space, apostrophe, colon, semi-colon, quote mark.

Ví dụ hợp lệ:
```
Win.Trojan.Agent-12345-1
Unix.Malware.Rootkit-67890-2
```

---

## 3. Hash-based Signatures

### 3.1. File Hash Signatures (.hdb / .hsb)

**Định dạng:**
```
HashString:FileSize:MalwareName[:min_flevel[:max_flevel]]
```

**Ví dụ - MD5 (.hdb):**
```
48c4533230e1ae1c118c741c0db19dfb:17387:Win.Trojan.Test
```

**Ví dụ - SHA1/SHA256 (.hsb):**
```
cf3d586265dde0c8d728972891ca7d14b4a083ba:151768:Win.Trojan.Agent
```

> ClamAV tự động nhận diện hash type dựa trên độ dài chuỗi hash.

### 3.2. PE Section Hash Signatures (.mdb / .msb)

**Định dạng:**
```
PESectionSize:PESectionHash:MalwareName
```

**Ví dụ:**
```
83456:83620eda4d054fe35c19faaa89d515f3:Win.Trojan.Packed
```

> **Lưu ý quan trọng**: Thứ tự `Size:Hash` ngược với `.hdb` (`Hash:Size`).

### 3.3. PE Import Table Hash (.imp)

**Định dạng:**
```
PEImportTableHash:PEImportTableSize:MalwareName
```

**Ví dụ:**
```
98c88d882f01a3f6ac1e5f7dfd761624:39:calc.exe
```

### 3.4. Hash với kích thước không xác định

Khi không biết kích thước file, dùng `*` thay cho size. **Yêu cầu min_flevel >= 73**.

```
# .hsb với size wildcard
5b852928a129d63dc5c895bd62cf2ab7:*:Trojan.Generic:73

# .msb với size wildcard
*:6555d93d90a4642c9b3feb4bdb075ec1:Win.Trojan.Packed:73
```

### 3.5. Tạo hash signature với sigtool

```bash
# Tạo MD5 signature
sigtool --md5 suspicious.exe > mysignatures.hdb

# Tạo SHA1 signature  
sigtool --sha1 suspicious.exe > mysignatures.hsb

# Tạo SHA256 signature
sigtool --sha256 suspicious.exe > mysignatures.hsb

# Tạo PE section hash signature
sigtool --mdb suspicious.exe > mysignatures.mdb

# Tạo PE import table hash
sigtool --imp suspicious.exe > mysignatures.imp
```

### 3.6. Giới hạn của Hash Signatures

| Ưu điểm | Nhược điểm |
|---------|-----------|
| Rất nhanh (O(1) lookup) | Chỉ phát hiện file **static** (không thay đổi 1 byte) |
| Không false positive | Dễ bị bypass bằng cách thay đổi 1 byte |
| Đơn giản, dễ triển khai | Không dùng được cho text/HTML/JS (bị normalize) |

---

## 4. Extended Signatures (.ndb)

### 4.1. Định dạng cơ bản

```
MalwareName:TargetType:Offset:HexSignature[:min_flevel[:max_flevel]]
```

### 4.2. Target Types

| Giá trị | Loại file |
|---------|-----------|
| 0 | Any file (bất kỳ) |
| 1 | Portable Executable (PE) - Windows EXE/DLL/SYS |
| 2 | OLE2 component (VBA script, Office macro) |
| 3 | HTML (đã normalize) |
| 4 | Mail file |
| 5 | Graphics |
| 6 | ELF (Linux/Unix executable) |
| 7 | ASCII text file (đã normalize) |
| 8 | Unused |
| 9 | Mach-O (macOS executable) |
| 10 | PDF |
| 11 | Flash (SWF) |
| 12 | Java |

### 4.3. Offset Types

| Offset | Ý nghĩa |
|--------|---------|
| `*` | Bất kỳ vị trí nào trong file |
| `n` | Offset tuyệt đối từ đầu file (byte n) |
| `EOF-n` | n bytes từ cuối file |
| `EP+n` | Entry Point + n bytes (PE/ELF/Mach-O) |
| `EP-n` | Entry Point - n bytes |
| `Sx+n` | Start of section x + n bytes (x đếm từ 0) |
| `SEx` | Toàn bộ section x |
| `SL+n` | Start of last section + n bytes |

### 4.4. Floating Offsets

Thêm `,MaxShift` để match trong khoảng:
```
Offset,MaxShift
```

Ví dụ:
```
10,5     # Match từ offset 10 đến 15
EP+0,20  # Match từ EP đến EP+20
```

### 4.5. Hex Signature Wildcards

| Ký hiệu | Ý nghĩa |
|---------|---------|
| `??` | Match bất kỳ byte nào |
| `a?` | Match high nibble (4 bit cao) = a0-af |
| `?a` | Match low nibble (4 bit thấp) = 0a-fa |
| `*` | Match bất kỳ số byte (0 hoặc nhiều) |
| `{n}` | Match đúng n bytes |
| `{n-}` | Match n hoặc nhiều hơn bytes |
| `{-n}` | Match n hoặc ít hơn bytes |
| `(aa\|bb\|cc)` | Match aa HOẶC bb HOẶC cc |
| `HEXSIG[x-y]aa` | Match aa trong khoảng x-y bytes sau HEXSIG |

> **Quy tắc quan trọng**: `*` và `{}` chia hex-signature thành 2 phần. Mỗi phần phải chứa ít nhất 2 ký tự hex tĩnh (không phải wildcard).

### 4.6. Ví dụ Extended Signatures

```ndb
# Signature đơn giản - match bất kỳ đâu
Trojan.Win32.Test:0:*:4d5a90000300000004000000ffff0000

# Match tại offset cố định
Trojan.Win32.EP:1:0x1000:558bec6a00

# Match tại Entry Point
Trojan.Win32.EPMatch:1:EP+0:e800000000

# Match tại section 0
Trojan.Win32.Section0:1:S0+0:2e74657874000000

# Match từ cuối file
Trojan.Win32.EOF:0:EOF-10:deadbeef

# Floating offset
Trojan.Win32.Float:1:EP+0,50:558bec

# Sử dụng wildcards
Trojan.Win32.Wild:0:*:4d5a????????????0400

# Match nhiều lựa chọn
Trojan.Win32.Alt:0:*:558b(ec\|e5\|ed)

# Match với khoảng cách
Trojan.Win32.Gap:0:*:558bec{10-50}e800000000

# Yêu cầu engine level
Trojan.Win32.New:1:EP+0:558bec:80
```

---

## 5. Logical Signatures (.ldb)

### 5.1. Định dạng

```
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;Subsig2;...
```

### 5.2. TargetDescriptionBlock Keywords

| Keyword | Mô tả | Ví dụ |
|---------|-------|-------|
| `Engine:X-Y` | Yêu cầu engine functionality level | `Engine:81-255` |
| `Target:X` | Target file type | `Target:1` (PE) |
| `FileSize:X-Y` | Kích thước file (bytes) | `FileSize:1000-50000` |
| `EntryPoint:X-Y` | Entry point offset | `EntryPoint:0x1000-0x2000` |
| `NumberOfSections:X-Y` | Số section trong PE | `NumberOfSections:3-5` |
| `Container:CL_TYPE_*` | Loại container chứa file | `Container:CL_TYPE_ZIP` |
| `Intermediates:A>B>C` | Nhiều lớp container | `CL_TYPE_ZIP>CL_TYPE_PDF` |
| `IconGroup1:name` | Nhóm icon 1 từ .idb | `IconGroup1:malware_icons` |
| `IconGroup2:name` | Nhóm icon 2 từ .idb | `IconGroup2:fake_icons` |
| `HandlerType:CL_TYPE_*` | Rescan như loại file khác | `HandlerType:CL_TYPE_PDF` |

> **Lưu ý**: Nếu dùng `Engine`, phải đặt **đầu tiên** trong TargetDescriptionBlock.

### 5.3. Logical Expression

| Toán tử | Ý nghĩa |
|---------|---------|
| `A&B` | A AND B (cả hai phải match) |
| `A\|B` | A OR B (một trong hai match) |
| `A=X` | A match đúng X lần |
| `A=X,Y` | A match X lần, ít nhất Y signature khác nhau |
| `A>X` | A match nhiều hơn X lần |
| `A>X,Y` | A match >X lần, ít nhất Y signature khác nhau |
| `A<X` | A match ít hơn X lần |
| `A=0` | Negation (KHÔNG được match) |

### 5.4. Subsignature Modifiers (clamav-0.99+)

Thêm `::` sau hex signature:

| Modifier | Ý nghĩa |
|----------|---------|
| `i` | Case-insensitive |
| `w` | Wide (UTF-16LE, thêm NULL giữa các byte) |
| `a` | ASCII |
| `f` | Fullword (delimited by non-alphanumeric) |

Ví dụ:
```ldb
# Match 'AAAA' không phân biệt hoa thường
clamav-nocase;Engine:81-255,Target:0;0&1;41414141::i;424242::i

# Match 'hello' wide + ascii + fullword + nocase
clamav-wide;Engine:81-255,Target:0;0&1;414141;68656c6c6f::iwfa
```

### 5.5. Macro Subsignatures (clamav-0.96+)

Định dạng: `${min-max}MACROID$`

```ldb
# test.ldb
TestMacro;Engine:51-255,Target:0;0&1;616161;${6-7}12$

# test.ndb (macro group 12)
D1:0:$12:626262
D2:0:$12:636363
D3:0:$30:626264
```

Tương đương với:
```ldb
TestMacro;Engine:51-255,Target:0;0;616161{3-4}(626262\|636363)
```

### 5.6. PCRE Subsignatures (clamav-0.99+)

Định dạng: `Trigger/PCRE/[Flags]`

| Flag | Ý nghĩa |
|------|---------|
| `g` | Global - tìm TẤT CẢ match |
| `r` | Rolling - tìm từ offset chỉ định, không auto-anchor |
| `e` | Encompass - giới hạn trong offset và maxshift |
| `i` | Case-insensitive (PCRE) |
| `s` | DOTALL |
| `m` | MULTILINE |
| `x` | EXTENDED |

Ví dụ:
```ldb
# Tìm "clamav" sau khi subsig 0 match
Find.ClamAV;Engine:81-255,Target:0;1;6265676c6164697427736e6f7462797465636f6465;0/clamav/g

# Tìm regex phức tạp
Firefox.IDB.UseAfterFree;Engine:81-255,Target:0;0&1;4944424b657952616e6765;0/^\x2e(only\|lowerBound\|upperBound\|bound)\x28.*?\x29.*?\x2e(lower\|upper\|lowerOpen\|upperOpen)/smi
```

### 5.7. Byte Compare Subsignatures (clamav-0.101+)

Định dạng: `subsigid_trigger(offset#byte_options#comparisons)`

```ldb
# So sánh giá trị 4 bytes tại offset +8 từ subsig 0
# Trigger: subsig 0 match
# Offset: >>8 (8 bytes sau subsig 0)
# Byte options: hl4 = hex, little-endian, 4 bytes
# Comparison: >0x1000 = giá trị > 0x1000
CheckSize;Engine:101-255,Target:1;0&1;4d5a;0(>>8#hl4#>0x1000)
```

| byte_options | Ý nghĩa |
|-------------|---------|
| `h/d/a/i` | hex / decimal / auto / binary |
| `l/b` | little-endian / big-endian |
| `e` | exact (chỉ đánh giá nếu đọc đủ bytes) |
| `num_bytes` | Số bytes đọc (1,2,4,8 cho binary) |

### 5.8. Image Fuzzy Hash (clamav-0.105+)

Định dạng: `fuzzy_img#<hash>#<dist>`

```ldb
logo.png;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0
```

### 5.9. VersionInfo Matching (VI)

Dùng offset `VI` để match key/value trong PE version info:

```ndb
# Match "CompanyName" = "Microsoft Corporation"
my_test_vi_sig:1:VI:43006f006d00700061006e0079004e0061006d006500000000004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e000000
```

### 5.10. Ví dụ Logical Signatures phức tạp

```ldb
# Ví dụ 1: Match nếu có (subsig 0 HOẶC 1 HOẶC 2) VÀ subsig 3
Worm.Godog;Target:0;((0\|1\|2)&3);66696c65...;616c61...;7a6f6c77...;73746566...

# Ví dụ 2: Match nếu có ít nhất 6 trong 3 subsig khác nhau, và subsig 3
Sig2;Target:0;((0\|1\|2)>5,2)&3;6b6f74656b;616c61;7a6f6c77;73746566

# Ví dụ 3: PE với entry point cụ thể và section cụ thể
Sig4;Engine:51-255,Target:1;((0\|1)&(2\|3))&4;
EP+123:33c06834f04100f2aef7d14951684cf04100e8110a00;
S2+78:22??232c2d252229{-15}6e6573(63\|64)61706528;
S3+50:68efa311c3b9963cb1ee8e586d32aeb9043e;
f9c58dcf43987e4f519d629b103375;
SL+550:6300680065005c0046006900

# Ví dụ 4: Container - file trong ZIP
ZipMalware;Target:0,Container:CL_TYPE_ZIP;0;504b0304

# Ví dụ 5: HandlerType - rescan như PDF
Filetype.PDF;Engine:54-255,Target:0,HandlerType:CL_TYPE_PDF;(0\|1)&2&3;
0:255044462d??2e;0:257064662d??2e;737461727478726566;2525454f46
```

---

## 6. Container Metadata Signatures (.cdb)

### 6.1. Định dạng

```
VirusName:ContainerType:ContainerSize:FileNameREGEX:
FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:
Res1:Res2[:MinFL[:MaxFL]]
```

### 6.2. Các trường

| Trường | Mô tả |
|--------|-------|
| `VirusName` | Tên virus hiển thị khi match |
| `ContainerType` | Loại container (CL_TYPE_ZIP, CL_TYPE_RAR,...) hoặc `*` |
| `ContainerSize` | Kích thước container (bytes hoặc range x-y) |
| `FileNameREGEX` | Regex tên file trong container |
| `FileSizeInContainer` | Kích thước nén (bytes hoặc range) |
| `FileSizeReal` | Kích thước giải nén (bytes hoặc range) |
| `IsEncrypted` | 1=encrypted, 0=not, `*`=ignore |
| `FilePos` | Vị trí file trong container (đếm từ 1) |
| `Res1` | CRC hex (ZIP/RAR) hoặc ignored |
| `Res2` | Không dùng (để `*`) |

### 6.3. Container Types

- `CL_TYPE_ZIP`, `CL_TYPE_RAR`, `CL_TYPE_ARJ`
- `CL_TYPE_MSCAB`, `CL_TYPE_7Z`
- `CL_TYPE_MAIL`
- `CL_TYPE_POSIX_TAR`, `CL_TYPE_OLD_TAR`
- `CL_TYPE_CPIO_OLD`, `CL_TYPE_CPIO_ODC`, `CL_TYPE_CPIO_NEWC`, `CL_TYPE_CPIO_CRC`

### 6.4. Ví dụ

```cdb
# Phát hiện file .exe trong ZIP có tên suspicious
Trojan.ZipExe:CL_TYPE_ZIP:*:*\.exe$:1000-50000:2000-100000:0:1:*:*

# Phát hiện file encrypted trong RAR
Trojan.EncryptedRar:CL_TYPE_RAR:*:*:100:100:1:1:*:*

# Phát hiện file trong container bất kỳ
Trojan.AnyContainer:*:*:*\.dll$:5000:5000:0:2:*:*
```

---

## 7. Bytecode Signatures (.cbc)

### 7.1. Khái niệm

Bytecode Signatures là plugin độc lập nền tảng, viết bằng C, biên dịch ra ngôn ngữ trung gian "bytecode". ClamAV thông dịch bytecode để thực thi.

**Đặc điểm:**
- Có thể parse file phức tạp hơn signature thông thường
- Có thể gọi API để đánh dấu file độc hại
- Một bytecode signature có thể phát hiện nhiều loại malware khác nhau
- Phân phối trong `bytecode.cvd` hoặc `bytecode.cld`

### 7.2. Cảnh báo bảo mật

> **CẢNH BÁO**: KHÔNG BAO GIỜ chạy bytecode từ nguồn không đáng tin cậy. Có thể dẫn đến thực thi mã tùy ý.

```bash
# Cho phép load bytecode không ký số (KHÔNG KHUYẾN NGHỊ trong production)
clamscan --bytecode-unsigned=yes
```

### 7.3. Công cụ clambc

```bash
# Xem thông tin bytecode
clambc --info signature.cbc

# In source code
clambc --printsrc signature.cbc

# In IR (Intermediate Representation)
clambc --printbcir signature.cbc

# Chạy test với file input
clambc --input file.bin --debug signature.cbc

# Force interpreter (không dùng JIT)
clambc --force-interpreter signature.cbc
```

### 7.4. Ví dụ output clambc --info

```
Bytecode format functionality level: 6
Bytecode metadata:
    compiler version: 0.105.0
    compiled on: (1719557581) Fri Jun 28 14:53:01 2024
    target exclude: 0
    bytecode type: logical only
    bytecode functionality level: 0 - 0
    bytecode logical signature: PRINT_FLAG.{Fake,Real};Engine:56-255,Target:0;0;0:4d5a
    virusname prefix: (null)
    virusnames: 0
    bytecode triggered on: files matching logical signature
    number of functions: 2
    number of types: 25
```

---

## 8. Phishing Signatures (.pdb, .gdb, .wdb)

### 8.1. Nguyên lý hoạt động

ClamAV phát hiện phishing bằng cách so sánh **Display URL** (URL hiển thị cho user) và **Real URL** (URL thực sự trong href).

```html
<!-- Ví dụ phishing -->
<a href="http://evil.com">http://www.paypal.com</a>

<!-- Real URL:    http://evil.com -->
<!-- Display URL: http://www.paypal.com -->
```

### 8.2. PDB format (Phishing Domain Blocklist)

```
R:DisplayedURL[:FuncLevelSpec]
H:DisplayedHostname[:FuncLevelSpec]
```

| Prefix | Ý nghĩa |
|--------|---------|
| `R` | Regex cho toàn bộ URL (RealURL:DisplayedURL) |
| `H` | Match hostname hoặc subdomain |

Ví dụ:
```pdb
# Match paypal.com và subdomain
H:paypal.com

# Match regex
R:.+\.paypal\.(com\|co\.uk)([/?].*)?

# Giới hạn engine version
H:amazon.co.uk:20-30
```

### 8.3. WDB format (Whitelist Database)

```
X:RealURL:DisplayedURL[:FuncLevelSpec]
Y:RealURL[:FuncLevelSpec]
M:RealHostname:DisplayedHostname[:FuncLevelSpec]
```

| Prefix | Ý nghĩa |
|--------|---------|
| `X` | Regex cho cả RealURL và DisplayedURL |
| `Y` | Regex chỉ cho RealURL (safe-browsing URLs) |
| `M` | Match hostname/subdomain |

Ví dụ:
```wdb
# Cho phép Amazon country domains link đến amazon.com
X:.+\.amazon\.(at\|ca\|co\.uk\|co\.jp\|de\|fr)([/?].*)?:.+\.amazon\.com([/?].*)?:17-

# Cho phép subdomain của google
M:www.google.ro:www.google.com
```

### 8.4. GDB format (Google Safe Browsing)

```
S:P:HostPrefix[:FuncLevelSpec]
S:F:Sha256hash[:FuncLevelSpec]
S1:P:HostPrefix[:FuncLevelSpec]
S1:F:Sha256hash[:FuncLevelSpec]
S2:P:HostPrefix[:FuncLevelSpec]
S2:F:Sha256hash[:FuncLevelSpec]
S:W:Sha256hash[:FuncLevelSpec]
```

| Prefix | Ý nghĩa |
|--------|---------|
| `S:P:` | Google Safe Browsing - malware sites prefix |
| `S:F:` | Google Safe Browsing - malware sites hash |
| `S1:P:` | Phishing sites prefix |
| `S1:F:` | Phishing sites hash |
| `S2:P:` | Google Safe Browsing - phishing prefix |
| `S:W:` | Locally allowed hashes |

### 8.5. Flags cho PDB

| Flag | Value | Mô tả |
|------|-------|-------|
| HOST_SUFFICIENT | 1 | |
| DOMAIN_SUFFICIENT | 2 | |
| DO_REVERSE_LOOKUP | 4 | |
| CHECK_REDIR | 8 | |
| CHECK_SSL | 16 | |
| CHECK_CLOAKING | 32 | |
| CLEANUP_URL | 64 | |
| CHECK_DOMAIN_REVERSE | 128 | |
| CHECK_IMG_URL | 256 | |
| DOMAINLIST_REQUIRED | 512 | |

Flags mặc định: `CLEANUP_URL | CHECK_SSL | CHECK_CLOAKING | CHECK_IMG_URL`

Ví dụ sử dụng flags:
```pdb
# Không check images cho ebay.com
# 2|256 = 258 = 0x102
R102:www.ebay.com:.+
```

---

## 9. YARA Rules

### 9.1. Hỗ trợ trong ClamAV

ClamAV có thể parse file `.yar` và `.yara` như signature database.

### 9.2. Giới hạn

| Tính năng | Trạng thái |
|-----------|-----------|
| YARA modules (`import`) | ❌ Không hỗ trợ |
| Global rules (`global`) | ❌ Không hỗ trợ |
| External variables (`contains`, `matches`) | ❌ Không hỗ trợ |
| Pre-compiled rules (`yarac`) | ❌ Không hỗ trợ |
| Strings + wildcards (>= 2 octets) | ✅ Hỗ trợ |
| Tối đa 64 strings/rule | ✅ Hỗ trợ |
| Phải có ít nhất 1 string (literal/hex/regex) | ✅ Bắt buộc |

### 9.3. Ảnh hưởng của ClamAV processing

| Tính năng | Ảnh hưởng |
|-----------|-----------|
| File decomposition | YARA match cả file giải nén |
| Normalization (HTML/JS/Text) | YARA match trên file đã normalize |
| `--normalize=no` | Ngăn normalization (clamav 0.100+) |
| `--scan-html=no` | Ngăn HTML normalization (pre-0.99.2) |

### 9.4. Ví dụ YARA rule cho ClamAV

```yara
rule CheckFileSize
{
  strings:
    $abc = "abc"
  condition:
    ($abc or not $abc) and filesize < 200KB
}

rule Trojan_Win32_Example
{
  meta:
    description = "Detects example trojan"
    author = "Analyst"

  strings:
    $mz = { 4d 5a }
    $code = { 55 8b ec 6a 00 }
    $string1 = "evil_function" wide ascii
    $string2 = /http:\/\/evil\.[a-z]{3,6}\/payload/

  condition:
    $mz at 0 and $code and ($string1 or $string2)
}
```

### 9.5. Triển khai YARA trong ClamAV

```bash
# Copy YARA rules vào database directory
cp myrules.yar /var/lib/clamav/

# Restart services
systemctl restart clamav-daemon

# Kiểm tra
grep yara /var/log/clamav/clamav.log
```

---

## 10. Các công cụ hỗ trợ (sigtool)

### 10.1. Tạo signature

```bash
# Tạo hex dump
echo -n "Match on this" | sigtool --hex-dump
# Output: 4d61746368206f6e2074686973

# Tạo MD5 signature
sigtool --md5 malware.exe > signatures.hdb

# Tạo SHA1/SHA256
sigtool --sha1 malware.exe > signatures.hsb
sigtool --sha256 malware.exe > signatures.hsb

# Tạo PE section hash
sigtool --mdb malware.exe > signatures.mdb

# Tạo PE import hash
sigtool --imp malware.exe > signatures.imp
```

### 10.2. Normalize file

```bash
# Normalize HTML
sigtool --html-normalise suspicious.html
# Tạo: nocomment.html, notags.html, javascript

# Normalize ASCII text
sigtool --ascii-normalise suspicious.txt
# Tạo: normalised_text
```

### 10.3. Decode và test signature

```bash
# Decode signature
sigtool --decode < signature.ldb

# Test signature với file
sigtool --test-sigs signature.ndb malware.exe

# Xem thông tin CVD
sigtool --info main.cvd

# Giải nén CVD
sigtool --unpack main.cvd

# In certificates của PE
sigtool --print-certs malware.exe

# Extract VBA macros
sigtool --vba document.doc
```

### 10.4. Debug với clamscan

```bash
# Debug chi tiết
clamscan --debug --leave-temps malware.exe

# Tăng giới hạn scan
clamscan --max-filesize=2000M --max-scansize=2000M \
         --max-files=2000000 --max-recursion=2000000 \
         --max-embeddedpe=2000M malware.exe

# Quét với custom database
clamscan -d mysignatures.ndb suspicious_directory/

# Chỉ load custom db (KHÔNG load CVD mặc định)
clamscan -d mysignatures.ndb --no-default-db file.exe
```

---

## 11. Quy trình xây dựng công cụ chống virus

### 11.1. Kiến trúc đề xuất

```
┌─────────────────────────────────────────────────────────────┐
│                    ANTI-VIRUS ENGINE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   INPUT      │───▶│  FILE TYPE   │───▶│ DECOMPRESS   │  │
│  │  MODULE      │    │  DETECTION   │    │  & EXTRACT   │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                  │          │
│  ┌──────────────┐    ┌──────────────┐           │          │
│  │   REPORT     │◀───│  SIGNATURE   │◀──────────┘          │
│  │   MODULE     │    │   MATCHING   │                      │
│  └──────────────┘    └──────┬───────┘                      │
│                             │                               │
│  ┌──────────────────────────┴──────────────────────────┐   │
│  │              SIGNATURE DATABASES                      │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐        │   │
│  │  │ .hdb   │ │ .ndb   │ │ .ldb   │ │ .yar   │        │   │
│  │  │ .hsb   │ │ .mdb   │ │ .cdb   │ │ .cbc   │        │   │
│  │  │ .imp   │ │ .msb   │ │ .idb   │ │ .pdb   │        │   │
│  │  └────────┘ └────────┘ └────────┘ └────────┘        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 11.2. Các bước triển khai

#### Bước 1: Thu thập mẫu malware
```bash
# Thu thập từ sandbox
# Thu thập từ VirusTotal, MalwareBazaar
# Phân loại theo family, platform
```

#### Bước 2: Tạo hash signatures (nhanh, chính xác)
```bash
# Batch tạo hash cho tất cả mẫu
for f in malware_samples/*; do
    sigtool --md5 "$f" >> signatures.hdb
    sigtool --sha256 "$f" >> signatures.hsb
done
```

#### Bước 3: Tạo body-based signatures (generic)
```bash
# Tìm common bytes giữa các variant
# Dùng sigtool --hex-dump để xem nội dung
# Tạo .ndb với wildcards cho phù hợp
```

#### Bước 4: Tạo logical signatures (phức tạp)
```bash
# Kết hợp nhiều pattern
# Dùng logical operators để giảm false positive
# Thêm PCRE nếu cần pattern phức tạp
```

#### Bước 5: Container signatures
```bash
# Phát hiện malware trong archive
# Dùng .cdb để match metadata
```

#### Bước 6: Test và tinh chỉnh
```bash
# Test với clean files để tránh false positive
clamscan -d mysignatures.ndb clean_samples/

# Test với malware samples
clamscan -d mysignatures.ndb malware_samples/

# Debug nếu không match
clamscan --debug --leave-temps -d mysignatures.ndb malware.exe
```

#### Bước 7: Đóng gói và phân phối
```bash
# Tạo CVD (cần private key của Cisco-Talos)
# Hoặc phân phối dạng text database
# Dùng freshclam để cập nhật tự động
```

---

## 12. Ví dụ thực tế - Xây dựng hệ thống quét đơn giản

### 12.1. Kịch bản: Phát hiện trojan giả mạo PDF

#### Mẫu malware: `fake_pdf.exe`
- PE file có icon PDF
- Chứa chuỗi "PDF" trong version info
- Có section UPX
- Kết nối đến C2: `evil-c2.example.com`

#### Bước 1: Thu thập thông tin

```bash
# Xác định file type
clamscan --debug fake_pdf.exe
# Output: Recognized MS-EXE/DLL file
#         File type: Executable
#         Section 0: UPX0
#         Section 1: UPX1

# Xem version info
clamscan --debug fake_pdf.exe | grep -i versioninfo
# VersionInfo: 'FileDescription'='Adobe PDF Document'

# Xem strings
strings fake_pdf.exe | grep -i "evil\|pdf\|http"
# evil-c2.example.com
# http://evil-c2.example.com/payload
```

#### Bước 2: Tạo các loại signature

**Hash signature (.hdb):**
```bash
sigtool --md5 fake_pdf.exe
# Output: a1b2c3d4e5f678901234567890123456:15432:fake_pdf.exe
```

```hdb
# signatures.hdb
Trojan.Win32.FakePDF.A:a1b2c3d4e5f678901234567890123456:15432
```

**Extended signature (.ndb):**
```ndb
# Phát hiện PE có chuỗi "evil-c2.example.com"
Trojan.Win32.FakePDF.B:1:*:6576696c2d63322e6578616d706c652e636f6d

# Phát hiện tại entry point (sau khi unpack)
Trojan.Win32.FakePDF.C:1:EP+0:558bec6a0068????????e8
```

**Logical signature (.ldb):**
```ldb
# Kết hợp nhiều dấu hiệu
Trojan.Win32.FakePDF.D;Engine:81-255,Target:1,IconGroup1:pdf_icons;
(0&1&2)&(3\|4);
# Subsig 0: PE header
0:4d5a;
# Subsig 1: UPX section name
1:5550583000000000;
# Subsig 2: Version info "Adobe"
2:VI:410064006f00620065;
# Subsig 3: C2 domain
3:6576696c2d63322e6578616d706c652e636f6d::i;
# Subsig 4: HTTP request
4:687474703a2f2f::i
```

**Icon signature (.idb):**
```idb
# Tạo từ debug output
# clamscan --debug fake_pdf.exe | grep "ICO SIGNATURE"
FakePDF_Icon:pdf_icons:malware_icons:18e2e0304ce60a0cc3a09053a30000414100057e000afe0000e80006e510078b0a08910d11ad04105e0811510f084e01040c080a1d0b0021000a39002a41
```

**Container signature (.cdb):**
```cdb
# Phát hiện fake_pdf.exe trong ZIP
Trojan.FakePDF.Zip:CL_TYPE_ZIP:*:fake_pdf\.exe$:15000:15000:0:1:*:*
```

#### Bước 3: Test signature

```bash
# Tạo test database
cat > test_signatures.ndb << 'EOF'
Trojan.Win32.FakePDF.B:1:*:6576696c2d63322e6578616d706c652e636f6d
EOF

# Test quét
clamscan -d test_signatures.ndb fake_pdf.exe
# fake_pdf.exe: Trojan.Win32.FakePDF.B.UNOFFICIAL FOUND

# Test với clean file
clamscan -d test_signatures.ndb /bin/ls
# /bin/ls: OK
```

#### Bước 4: Tạo hệ thống quét tự động

```bash
#!/bin/bash
# simple_av_scanner.sh

DB_DIR="/opt/myav/signatures"
QUARANTINE="/opt/myav/quarantine"
LOG_FILE="/opt/myav/scan.log"

# Tạo thư mục
mkdir -p "$QUARANTINE"

# Quét thư mục
scan_directory() {
    local target="$1"
    echo "[$(date)] Bắt đầu quét: $target" >> "$LOG_FILE"

    clamscan \
        -d "$DB_DIR" \
        --recursive \
        --infected \
        --log="$LOG_FILE" \
        --move="$QUARANTINE" \
        "$target"

    echo "[$(date)] Kết thúc quét" >> "$LOG_FILE"
}

# Quét file đơn lẻ
scan_file() {
    local file="$1"
    result=$(clamscan -d "$DB_DIR" --no-summary "$file" 2>/dev/null)

    if echo "$result" | grep -q "FOUND"; then
        virus_name=$(echo "$result" | grep "FOUND" | awk -F: '{print $2}' | sed 's/ FOUND//')
        echo "PHÁT HIỆN: $file -> $virus_name"
        mv "$file" "$QUARANTINE/"
        echo "[$(date)] QUARANTINE: $file ($virus_name)" >> "$LOG_FILE"
        return 1
    else
        echo "SẠCH: $file"
        return 0
    fi
}

# Main
case "$1" in
    dir)
        scan_directory "$2"
        ;;
    file)
        scan_file "$2"
        ;;
    *)
        echo "Usage: $0 {dir\|file} <path>"
        exit 1
        ;;
esac
```

### 12.2. Kịch bản: Phát hiện phishing email

#### Mẫu: Email giả mạo Amazon

```html
<!-- email.eml -->
<html>
<body>
<a href="http://evil-phish.example.com/login">
  http://www.amazon.com/signin
</a>
</body>
</html>
```

#### Tạo phishing signatures

```pdb
# daily.pdb - Blocklist
H:amazon.com
H:paypal.com
R:.+\.amazon\.(com\|co\.uk\|de\|fr)([/?].*)?
```

```wdb
# daily.wdb - Whitelist
# Cho phép Amazon redirect hợp lệ
X:.+\.amazon\.(at\|ca\|co\.uk\|co\.jp\|de\|fr)([/?].*)?:.+\.amazon\.com([/?].*)?:17-
```

#### Test

```bash
clamscan --phishing-sigs=yes email.eml
# LibClamAV info: Suspicious link found!
# LibClamAV info:   Real URL:    http://evil-phish.example.com/login
# LibClamAV info:   Display URL: http://www.amazon.com/signin
# email.eml: Heuristics.Phishing.Email.SpoofedDomain FOUND
```

### 12.3. Kịch bản: Phát hiện malware trong archive

#### Tạo container signature

```cdb
# Phát hiện file .scr (screensaver) trong ZIP - thường là malware
Trojan.Screensaver.Zip:CL_TYPE_ZIP:*:*\.scr$:1000-10000000:1000-10000000:0:1:*:*

# Phát hiện file double extension trong RAR
Trojan.DoubleExt.Rar:CL_TYPE_RAR:*\.(pdf\|doc\|xls)\.exe$:1000-500000:1000-500000:0:1:*:*

# Phát hiện file encrypted trong ZIP (ransomware pattern)
Ransomware.EncryptedZip:CL_TYPE_ZIP:*:*:100:100:1:1:*:*
```

---

## Phụ lục A: Target Types Reference

| Value | Name | Description |
|-------|------|-------------|
| 0 | ANY | Any file type |
| 1 | PE | Windows Portable Executable |
| 2 | OLE2 | OLE2 containers (Office docs) |
| 3 | HTML | Normalized HTML |
| 4 | MAIL | Email format |
| 5 | GRAPHICS | Image files |
| 6 | ELF | Linux ELF executable |
| 7 | ASCII | Normalized ASCII text |
| 8 | UNUSED | Reserved |
| 9 | MACHO | macOS Mach-O |
| 10 | PDF | PDF documents |
| 11 | FLASH | Flash/SWF files |
| 12 | JAVA | Java bytecode |

## Phụ lục B: Common Container Types

| Type | Description |
|------|-------------|
| CL_TYPE_ZIP | ZIP archives |
| CL_TYPE_RAR | RAR archives |
| CL_TYPE_ARJ | ARJ archives |
| CL_TYPE_MSCAB | Microsoft CAB |
| CL_TYPE_7Z | 7-Zip archives |
| CL_TYPE_MAIL | Email containers |
| CL_TYPE_POSIX_TAR | POSIX tar |
| CL_TYPE_OLD_TAR | Old tar format |
| CL_TYPE_CPIO_OLD | Old cpio |
| CL_TYPE_CPIO_ODC | ODC cpio |
| CL_TYPE_CPIO_NEWC | Newc cpio |
| CL_TYPE_CPIO_CRC | CRC cpio |
| CL_TYPE_GZIP | GZIP compressed |
| CL_TYPE_BZIP | BZIP2 compressed |
| CL_TYPE_XZ | XZ compressed |

## Phụ lục C: Quick Reference - Tạo Signature

```bash
# 1. Thu thập mẫu
mkdir -p samples/malware samples/clean

# 2. Tạo hash signatures
sigtool --md5 samples/malware/* > mysignatures.hdb
sigtool --sha256 samples/malware/* > mysignatures.hsb

# 3. Tạo body-based signatures
# - Dùng clamscan --debug --leave-temps để xem file sau xử lý
# - Tìm common bytes
# - Tạo .ndb với wildcards

# 4. Tạo logical signatures
# - Kết hợp nhiều .ndb patterns
# - Thêm điều kiện logic
# - Lưu vào .ldb

# 5. Test
clamscan -d mysignatures.ndb -d mysignatures.ldb samples/malware/
clamscan -d mysignatures.ndb -d mysignatures.ldb samples/clean/

# 6. Tinh chỉnh
# - Giảm false positives
# - Thêm wildcards cho variant
# - Cập nhật min_flevel nếu cần

# 7. Triển khai
# - Copy vào /var/lib/clamav/
# - Restart clamd
# - Theo dõi logs
```

## Phụ lục D: Cấu trúc CVD File

```
CVD File Structure:
┌────────────────────────────────────────┐
│ Header (512 bytes)                    │
│ ClamAV-VDB:build_time:version:         │
│ num_sigs:min_flevel:MD5:               │
│ digital_signature:builder:build_time  │
├────────────────────────────────────────┤
│ Compressed Data (zlib)                │
│ ├── main.ndb                          │
│ ├── main.ldb                          │
│ ├── main.hdb                          │
│ ├── main.mdb                          │
│ └── ...                               │
└────────────────────────────────────────┘

# Giải nén
sigtool --unpack main.cvd

# Xem thông tin
sigtool --info main.cvd
```

---

## Tài liệu tham khảo

- ClamAV Official Documentation: https://docs.clamav.net/manual/Signatures.html
- ClamAV Signature Creation Guide (PDF)
- YARA Documentation: https://virustotal.github.io/yara/
- Cisco Talos ClamAV Blog

---

*Document được biên soạn dựa trên tài liệu chính thức của ClamAV. Cập nhật: 2026.*
