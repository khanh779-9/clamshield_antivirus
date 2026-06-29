# ClamAV Signature Format Reference

> Nguồn: https://docs.clamav.net/manual/Signatures.html và các trang con

---

## 1. Giới thiệu

ClamAV dùng chữ ký (signatures) để phân biệt file sạch và file độc hại. Signatures chủ yếu dạng text, tuân theo các định dạng riêng của ClamAV. Từ ClamAV 0.99 trở đi hỗ trợ thêm YARA rules.

Các signatures được đóng gói trong CVD (ClamAV Virus Database) – container có chữ ký số, bảo đảm không bị sửa đổi bởi bên thứ ba. Dùng `freshclam` để tải về, `sigtool -u <database>` để giải nén.

---

## 2. Tổng quan Database Formats

### 2.1. Settings Databases

| Extension | Mô tả |
|-----------|-------|
| `*.cfg` | Dynamic config settings (DCONF) |
| `*.cat`, `*.crb` | Trusted & revoked PE certificates (Authenticode) |
| `*.ftm` | File Type Magic (FTM) – nhận diện kiểu file |

### 2.2. Signature Databases

**Body-based (nội dung):**

| Extension | Mô tả |
|-----------|-------|
| `*.ndb`, `*.ndu` | Extended signatures (body-based cơ bản) |
| `*.ldb`, `*.ldu`, `*.idb` | Logical signatures (kết hợp nhiều subsig bằng toán tử logic) |
| `*.cdb` | Container metadata signatures |
| `*.cbc` | Bytecode signatures (C code biên dịch thành bytecode) |
| `*.pdb`, `*.gdb`, `*.wdb` | Phishing URL signatures |

**Hash-based:**

| Extension | Mô tả |
|-----------|-------|
| `*.hdb`, `*.hsb`, `*.hdu`, `*.hsu` | File hash signatures (MD5/SHA1/SHA256) |
| `*.mdb`, `*.msb`, `*.mdu`, `*.msu` | PE section hash signatures |
| `*.imp` | PE import table hash signatures |

**Alternative:**

| Extension | Mô tả |
|-----------|-------|
| `*.yar`, `*.yara` | YARA rules |

### 2.3. Other Database Files

| Extension | Mô tả |
|-----------|-------|
| `*.fp`, `*.sfp` | File allow lists (false positive) |
| `*.ign`, `*.ign2` | Signature ignore lists |
| `*.pwdb` | Encrypted archive passwords |
| `*.info` | Database information (SHA-256 checksum) |

> **Lưu ý:** Database có đuôi tận cùng bằng `u` (vd: `.ndu`, `.ldu`) chỉ được load khi bật PUA (Potentially Unwanted Application) signatures (mặc định: tắt).

### 2.4. Signature Names

Signatures **chỉ** được dùng: alphanumeric, dash (`-`), dot (`.`), underscore (`_`).  
**Không** dùng: space, apostrophe, colon, semi-colon, quote mark.

Định dạng tên chính thức (Cisco-Talos):

```
{platform}.{category}.{name}-{signature id}-{revision}
```

Ví dụ:
- `Win.Trojan.Zusy-9935890-0`
- `Win.Malware.Zusy-9935891-0`
- `Html.Malware.Agent-9915974-0`
- `Java.Malware.CVE_2021_44228-9915817-0`

---

## 3. Body-based Signature Content Format

Đây là định dạng nội dung hex dùng trong tất cả body-based signatures (NDB, LDB, …).

### 3.1. Hexadecimal Format

Dùng `sigtool --hex-dump` để chuyển đổi dữ liệu thành hex string:

```
$ sigtool --hex-dump
How do I look in hex?
486f7720646f2049206c6f6f6b20696e206865783f0a
```

### 3.2. Wildcards

| Ký tự | Ý nghĩa |
|-------|---------|
| `??` | Match bất kỳ byte nào |
| `a?` | Match high nibble (4 bit cao) |
| `?a` | Match low nibble (4 bit thấp) |
| `*` | Match bất kỳ số byte nào (chia signature thành 2 phần) |
| `{n}` | Match đúng `n` bytes |
| `{-n}` | Match `n` hoặc ít hơn bytes |
| `{n-}` | Match `n` hoặc nhiều hơn bytes |
| `{n-m}` | Match từ `n` đến `m` bytes |
| `HEXSIG[x-y]aa` / `aa[x-y]HEXSIG` | Match range any bytes, 1 bên là single-byte (`aa`), bên kia ≥2 bytes. `y` ≤ 32 |

**Ví dụ về `[x-y]`:**
```
testsig;Target:0;0;64[4-4]61616161{2}6262[3-6]65:27
```
- `64[4-4]61616161`: tìm byte `64` theo sau bởi `61616161` với đúng 4 bytes bất kỳ ở giữa.
- `6262[3-6]65`: tìm `6262` theo sau bởi `65` với 3-6 bytes bất kỳ ở giữa.

**Lưu ý về `*` và `{}`:** Khi range wildcard chia signature thành 2 sub-signature, mỗi sub-signature phải có ít nhất một block 2 ký tự static. Ngoại lệ: `{n}` với `n < 128` được tối ưu thành `n` ký tự `??` (không chia signature, không yêu cầu 2 static char).

### 3.3. Character Classes

| Ký tự | Ý nghĩa |
|-------|---------|
| `(B)` | Match word boundary (bao gồm file boundaries) |
| `(L)` | Match CR, CRLF hoặc file boundaries |
| `(W)` | Match non-alphanumeric character |

### 3.4. Alternate Strings

**Single-byte alternates** (từ 0.96):
```
(aa|bb|cc|...)
!(aa|bb|cc|...)
```
- Match một byte trong tập (hoặc negation: không trong tập).
- Không dùng được signature modifiers hay wildcards.

**Multi-byte fixed length alternates** (từ 0.98.2):
```
(aaaa|bbbb|cccc|...)
!(aaaa|bbbb|cccc|...)
```
- Tất cả phần tử phải cùng độ dài.
- Negation được hỗ trợ.

**Generic alternates** (từ 0.99):
```
(alt1|alt2|alt3|...)
```
- Độ dài variable.
- Không hỗ trợ negation.
- Được dùng signature modifiers và nibble wildcards (`??`, `a?`, `?a`).
- Ranged wildcards chỉ được `{n-m}` với `n-m < 128`.

> **Note:** Nếu dùng signature modifiers/wildcards với single-byte hoặc multi-byte alternates, chúng được phân loại lại thành generic alternate (mất negation, ảnh hưởng hiệu năng nhẹ).

---

## 4. Extended Signatures (*.ndb)

Định dạng body-based cơ bản nhất hiện nay (sau khi `.db` bị deprecated).

```
MalwareName:TargetType:Offset:HexSignature[:min_flevel[:max_flevel]]
```

| Field | Mô tả |
|-------|-------|
| `MalwareName` | Tên virus, theo chuẩn Signature Names |
| `TargetType` | Số nguyên chỉ loại file đích (xem Target Types) |
| `Offset` | Vị trí offset: `*` (any), `n` (absolute), `EOF-n`, `EP+n`, `EP-n`, `Sx+n`, `SEx`, `SL+n` |
| `HexSignature` | Nội dung hex body-based (xem Body Signature Format) |
| `min_flevel` | (optional) FLEVEL tối thiểu |
| `max_flevel` | (optional, cần min_flevel) FLEVEL tối đa |

**Floating offsets:** `Offset,MaxShift` – match mọi offset từ `Offset` đến `Offset+MaxShift`.  
Ví dụ: `10,5` match offset 10-15; `EP+n,y` match `EP+n` đến `EP+n+y`.

**Offset modifiers cho PE/ELF/Mach-O:**
- `*` = bất kỳ
- `n` = absolute offset
- `EOF-n` = cuối file trừ n bytes
- `EP+n` / `EP-n` = entry point +/- n
- `Sx+n` = start của section x + n
- `SEx` = entire section x
- `SL+n` = start của last section + n

---

## 5. Logical Signatures (*.ldb, *.idb)

Cho phép kết hợp nhiều subsignature bằng toán tử logic. Format:

```
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;Subsig2;...
```

### 5.1. TargetDescriptionBlock

Các cặp `Arg:Val` cách nhau bằng dấu phẩy:

| Keyword | Mô tả |
|---------|-------|
| `Engine:X-Y` | FLEVEL range (phải là keyword đầu tiên nếu dùng) |
| `Target:X` | Target type number |
| `FileSize:X-Y` | File size range (bytes) |
| `EntryPoint:X-Y` | Entry point offset range |
| `NumberOfSections:X-Y` | Số section range (executable) |
| `Container:CL_TYPE_*` | Container file type; `CL_TYPE_ANY` = root object |
| `Intermediates:CL_TYPE_*>CL_TYPE_*` | Nhiều layer container (tối đa 16 layers, dùng `>` ngăn cách, từ 0.100.0) |
| `IconGroup1` | Icon group name 1 từ .idb |
| `IconGroup2` | Icon group name 2 từ .idb |
| `HandlerType:CL_TYPE_*` | Không alert, mà re-scan file như kiểu khác (dùng để xác định file type) |

### 5.2. LogicalExpression

- **Basis clause:** `0, 1, ..., N` là index của `Subsig0 ... SubsigN`
- **Inductive clause:** Nếu `A, B` là sub-expressions và `X, Y` là số thập phân:
  - `(A&B)` – AND
  - `(A|B)` – OR
  - `A=X` – match đúng X lần
  - `A=X,Y` – X matches, ít nhất Y sigs khác nhau
  - `A>X` – match nhiều hơn X lần
  - `A>X,Y` – >X matches, ≥Y sigs khác nhau
  - `A<X` – match ít hơn X lần
  - `A<X,Y` – <X matches, ≥Y sigs khác nhau
  - `A=0` – negation (không được match)

### 5.3. Modifiers cho Subsignature (từ 0.99, Engine:81-255)

Dùng `::` sau hex pattern, theo sau bởi các ký tự:

| Ký tự | Flag | Ý nghĩa |
|-------|------|---------|
| `i` | Case-Insensitive | Match không phân biệt hoa thường |
| `w` | Wide | Match UTF-16 (chen NULL vào giữa các ký tự) |
| `f` | Fullword | Match từ được phân cách bởi non-alphanumeric |
| `a` | Ascii | Match ASCII. Kết hợp `aw` = cả ASCII và Wide |

Ví dụ:
```
clamav-nocase-A;Engine:81-255,Target:0;0&1;41414141::i;424242424242::i
clamav-fullword-B;Engine:81-255,Target:0;0&1;414141;68656c6c6f::fi
clamav-wide-B2;Engine:81-255,Target:0;0&1;414141;68656c6c6f::wa
```

### 5.4. Macro Subsignatures (từ 0.96, Engine:51-255)

Format: `${min-max}MACROID$`

Dùng để kết hợp nhiều NDB signatures thành alternates on-the-fly.

```
test.ldb:
    TestMacro;Engine:51-255,Target:0;0&1;616161;${6-7}12$

test.ndb:
    D1:0:$12:626262
    D2:0:$12:636363
```
Tương đương: `TestMacro;Engine:51-255,Target:0;0;616161{3-4}(626262|636363)`

- `MACROID` trỏ tới nhóm signatures (tối đa 32 groups)
- `{min-max}` là offset range relative tới subsig trước đó
- Macro subsig **không thể** là subsig đầu tiên

### 5.5. Byte Compare Subsignatures (từ 0.101)

Format: `subsigid_trigger(offset#byte_options#comparisons)`

Đánh giá giá trị số tại offset từ một matched subsig khác. Chạy sau tất cả subsig khác trừ PCRE.

- `subsigid_trigger`: ID của subsig trigger (non-PCRE, non-ByteCompare)
- `offset`: `>>` (positive) hoặc `<<` (negative) + số bytes
- `byte_options`: `[h|d|a|i][l|b][e]num_bytes`
  - `h`=hex, `d`=decimal, `a`=auto, `i`=raw binary
  - `l`=little endian, `b`=big endian
  - `e`=exact number of bytes
- `comparisons`: `Comparison_symbolComparison_value[,comparison_set]`
  - Symbols: `<`, `>`, `=`

### 5.6. PCRE Subsignatures (từ 0.99, Engine:81-255)

Format: `Trigger/PCRE/[Flags]`

- `Trigger`: LogicalExpression hợp lệ, chỉ tham chiếu subsig trước đó
- `PCRE`: regex string. Escape `/` bằng `\`. `;` phải viết là `\x3B`
- `Flags`:
  - `g` = global (ALL matches)
  - `r` = rolling (không auto-anchor)
  - `e` = encompass (confine giữa offset và maxshift)
  - `i` = PCRE_CASELESS
  - `s` = PCRE_DOTALL
  - `m` = PCRE_MULTILINE
  - `x` = PCRE_EXTENDED
  - `A` = PCRE_ANCHORED
  - `E` = PCRE_DOLLAR_ENDONLY
  - `U` = PCRE_UNGREEDY

### 5.7. Image Fuzzy Hash Subsignatures (từ 0.105)

Format: `fuzzy_img#<hash>#<dist>`

```
logo.png;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0
```

Tính năng này gần giống (nhưng không 100% giống) `phash()` của Python `imagehash` package.  
Để sinh hash, dùng: `clamscan --gen-json --debug /path/to/file` – hash xuất hiện trong JSON dưới key `ImageFuzzyHash`.

### 5.8. Version Information (VI) Signatures (từ 0.96)

Dùng anchor `VI` để match key/value pairs trong `VS_VERSION_INFORMATION` của PE files.

Format NDB test:
```
my_test_vi_sig:1:VI:paste_your_hex_sig_here
```

- Hex signature là UTF-16 dump của key và value
- Chỉ cho phép wildcards `??` và `(aa|bb)`
- `clamscan --debug` tự động in ra VI hex string

Decode VI hex:
```bash
echo hex_string | xxd -r -p | strings -el
```

### 5.9. Icon Signatures (*.idb)

Dành cho Logical Signatures dùng attribute `IconGroup1` / `IconGroup2`.

Format `.idb`:
```
ICONNAME:GROUP1:GROUP2:ICON_HASH
```

- `ICON_HASH` lấy từ debug output của libclamav
- Dùng fuzzy hash matching

---

## 6. Hash-based Signatures

### 6.1. File Hash Signatures

**.hdb (MD5):**
```
MD5Hash:FileSize:MalwareName
```
Ví dụ: `48c4533230e1ae1c118c741c0db19dfb:17387:test.exe`

**.hsb (SHA1/SHA256):**
```
HashString:FileSize:MalwareName
```

**Sinh bằng sigtool:**
```bash
sigtool --md5 test.exe > test.hdb
sigtool --sha256 test.exe > test.hsb
```

> **Quan trọng:** Không dùng hash signatures cho text files, HTML, hay dữ liệu bị preprocess. Dùng `--debug --leave-temps` để tạo signature cho preprocessed file.

### 6.2. PE Section Hash Signatures

**.mdb (MD5) / .msb (SHA1/SHA256):**
```
PESectionSize:PESectionHash:MalwareName
```

Sinh bằng:
```bash
sigtool --mdb /path/to/32bit/PE/file
```

> **Known issue:** 64-bit PE files (PE32+) chưa được hỗ trợ.

### 6.3. PE Import Table Hash Signatures (func. level 90)

**.imp:**
```
PEImportTableHash:PEImportTableSize:MalwareName
```

Sinh bằng:
```bash
sigtool --imp /path/to/32bit/PE/file
```

> **Known issues:** 64-bit PE chưa hỗ trợ. Wildcard `*` cho size bị broken đến 0.105.

### 6.4. Hash Signatures với Unknown Size

Dùng `*` trong size field, yêu cầu min functional level ≥ 73:
```
HashString:*:MalwareName:73
*:PESectionHash:MalwareName:73
```

---

## 7. YARA Rules (*.yar, *.yara)

ClamAV hỗ trợ YARA rules. File đuôi `.yar` / `.yara` được parse là YARA.

**Giới hạn:**
- YARA modules chưa hỗ trợ (không dùng `import`)
- Global rules không hỗ trợ
- External variables (`contains`, `matches`) không hỗ trợ
- Pre-compiled (`yarac`) không hỗ trợ
- Strings/wildcards segments phải ≥ 2 octets
- Tối đa 64 strings per rule
- Phải có ít nhất 1 literal/hex/regex string

**Lưu ý đặc thù ClamAV:**
- YARA rules match trên các file đã được decomposite/decompress
- Normalization (HTML, JS, ASCII text) được áp dụng trước khi YARA match
- Dùng `clamscan --normalize=no` để tắt normalization
- Tất cả YARA conditions đều được dẫn động bởi string matches

Ví dụ condition luôn chạy:
```perl
rule CheckFileSize
{
  strings:
    $abc = "abc"
  condition:
    ($abc or not $abc) and filesize < 200KB
}
```

---

## 8. Dynamic Configuration – DCONF (*.cfg)

Cho phép bật/tắt tính năng theo phiên bản engine.

Format:
```
Category:Flags:StartFlevel:EndFlevel
```

**Categories:** PE, ELF, MACHO, ARCHIVE, DOCUMENT, MAIL, OTHER, PHISHING, BYTECODE, STATS, PCRE

**Flags:** Bitmask override defaults. `0x0` = tắt tất cả options trong category.

**Ví dụ:** Tắt `OTHER_CONF_PDFNAMEOBJ` cho ClamAV 0.100.X (FLEVEL 90-99):
```
OTHER:0x6FF:90:99
```

Tham khảo bit definitions tại:
- https://github.com/Cisco-Talos/clamav/blob/main/libclamav/dconf.h
- https://github.com/Cisco-Talos/clamav/blob/main/libclamav/dconf.c

---

## 9. Authenticode Rules (*.crb, *.cat)

Kiểm tra signed PE files dựa trên certificate chain.

Format:
```
Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;minFL[;maxFL]]
```

| Field | Mô tả |
|-------|-------|
| `Name` | Tên entry |
| `Trusted` | 1=trusted, 0=revoked |
| `Subject` | SHA1 của Subject field (hex) |
| `Serial` | Serial number |
| `Pubkey` | Public key (hex) |
| `Exponent` | Exponent (hex, hiện hardcoded 010001) |
| `CodeSign` | 1=có thể sign code |
| `TimeSign` | 1=true |
| `CertSign` | 1=có thể sign certs khác |
| `NotBefore` | Integer, cert chưa hiệu lực trước timestamp này |
| `Comment` | Comments |

---

## 10. File Type Magic (*.ftm)

Cơ chế chính để ClamAV xác định kiểu file.

Format:
```
magictype:offset:magicbytes:name:rtype:type[:min_flevel[:max_flevel]]
```

| Field | Mô tả |
|-------|-------|
| `magictype` | 0=direct memory compare, 1=body-based format, 4=partition types |
| `offset` | Offset từ đầu file (`*` nếu magictype=1) |
| `magicbytes` | Magic bytes |
| `name` | Tên mô tả |
| `rtype` | File type đã phát hiện trước (thường `CL_TYPE_ANY` = wildcard) |
| `type` | CL_TYPE tương ứng |
| `min_flevel` | (optional) FLEVEL tối thiểu |
| `max_flevel` | (optional, cần min_flevel) FLEVEL tối đa |

---

## 11. Container Metadata Signatures (*.cdb)

Generic signatures cho file bên trong container.

Format:
```
VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
```

| Field | Mô tả |
|-------|-------|
| `VirusName` | Tên virus |
| `ContainerType` | `CL_TYPE_ZIP`, `CL_TYPE_RAR`, ... hoặc `*` = any |
| `ContainerSize` | Kích thước container (absolute hoặc range `x-y`) |
| `FileNameREGEX` | Regex cho tên file |
| `FileSizeInContainer` | Kích thước nén. Với MAIL/TAR/CPIO == FileSizeReal |
| `FileSizeReal` | Kích thước thật |
| `IsEncrypted` | 1=encrypted, 0=not, `*`=ignore |
| `FilePos` | Vị trí trong container (đếm từ 1) |
| `Res1` | CRC sum (ZIP/RAR), hex format; ignored với container khác |
| `Res2` | Không dùng (từ 0.96) |

---

## 12. Bytecode Signatures (*.cbc)

Cho phép viết C code để parse mẫu, biên dịch thành bytecode. Bytecode được interpret bởi ClamAV.

- File `.cbc` được đóng gói trong `bytecode.[cvd|cld]`
- Cung cấp API để truy cập sample data và metadata
- Một bytecode signature có thể trigger nhiều alert names khác nhau

Tài liệu chi tiết: https://github.com/Cisco-Talos/clamav-bytecode-compiler

---

## 13. Phishing Signatures (*.pdb, *.gdb, *.wdb)

### 13.1. PDB Format – Domain List

```
R:DisplayedURL[:FuncLevelSpec]
H:DisplayedHostname[:FuncLevelSpec]
```

- `R`: Regular expression cho concatenated URL
- `H`: Match hostname literal (có thể match subdomain)

### 13.2. GDB Format – URL Hashes (Google Safe Browsing)

```
S:P:HostPrefix[:FuncLevelSpec]
S:F:Sha256hash[:FuncLevelSpec]
S1:P:HostPrefix[:FuncLevelSpec]
S1:F:Sha256hash[:FuncLevelSpec]
S2:P:HostPrefix[:FuncLevelSpec]
S2:F:Sha256hash[:FuncLevelSpec]
S:W:Sha256hash[:FuncLevelSpec]
```

- `S:` = Google Safe Browsing malware
- `S2:` = Google Safe Browsing phishing
- `S1:` = Phishing.URL.Blocked
- `S:W:` = locally allowed hashes

### 13.3. WDB Format – Allow List

```
X:RealURL:DisplayedURL[:FuncLevelSpec]
Y:RealURL[:FuncLevelSpec]
M:RealHostname:DisplayedHostname[:FuncLevelSpec]
```

- `X`: Regex cho toàn bộ URL (RealURL:DisplayedURL), auto-anchored
- `Y`: Regex cho Real URL (từ ClamAV 1.6)
- `M`: Match hostname literal

### 13.4. Flags (Phishing)

| Flag | Value | Ý nghĩa |
|------|-------|---------|
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

Default: `CLEANUP_URL | CHECK_SSL | CHECK_CLOAKING | CHECK_IMG_URL`

### 13.5. Cách Matching Hoạt Động

1. Extract cặp RealURL/DisplayedURL từ HTML tags (anchor, form, img, iframe)
2. Normalize URL (cắt sau hostname)
3. Với allow list (WDB): nếu match, coi như sạch
4. Với domain list (PDB): nếu match, kiểm tra phishing
5. Heuristic: nếu DisplayURL và RealURL khác domain → phishing alert

---

## 14. Allow Lists (*.fp, *.sfp, *.ign, *.ign2)

### 14.1. File Allow Lists – *.fp / *.sfp

Cho phép một file cụ thể (dạng hash signature, đặt trong file `.fp` cho MD5, `.sfp` cho SHA):

```bash
sigtool --md5 /path/to/false/positive/file >> false-positives.fp
sigtool --sha256 /path/to/false/positive/file >> false-positives.sfp
```

### 14.2. Signature Ignore Lists – *.ign2

Bỏ qua một signature cụ thể:

```
Eicar-Test-Signature
```

Kèm MD5 của database entry (sẽ bỏ qua ignore nếu entry thay đổi):
```
Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c
```

`.ign` (cũ) vẫn hoạt động nhưng đã được thay thế bởi `.ign2`.

---

## 15. Encrypted Archive Passwords – Experimental (*.pwdb)

Cung cấp mật khẩu thử cho archive được mã hóa (hiện chỉ hỗ trợ ZIP với PKWARE encryption, từ 0.99 / flevel 81).

Format:
```
SignatureName;TargetDescriptionBlock;PWStorageType;Password
```

- `PWStorageType`: 0=cleartext, 1=hex
- `TargetDescriptionBlock`: `Engine:X-Y`, `Container:CL_TYPE_*`

---

## 16. Database Info (*.info)

File thông tin trong CVD/CLD archives, dùng để validate tính đúng đắn.

Format:
```
name:size:sha256
```

**Không thể load standalone** – chỉ tồn tại trong container chính thức.

---

## 17. Signature Naming Guidelines (Cisco-Talos)

### Platform (platform)

Andr, Archive, Asp, Cert, Clamav, Clean, Css, Doc, Dos, Eicar, Email, Embedded, Emf, Gif, Heuristics, Html, Hunting, Hwp, Img, Ios, Java, Js, Legacy, Lnk, Midi

### Category (category)

Adware, Backdoor, Coinminer, Countermeasure, Downloader, Dropper, Exploit, File, Filetype, Infostealer, Ircbot, Joke, Keylogger, Loader, Macro, Malware, Packed, Packer, Phishing, Proxy, Ransomware, Revoked, Rootkit, Spyware, Test

### Name (name)

Tên đại diện (thường là malware family name). Dùng "Agent" nếu không có tên phù hợp.

**Rules:**
- **Must:** chỉ dùng alphanumeric, dot, underscore
- **Must not:** space, apostrophe, quote marks; tên công ty/thương hiệu/người thật; tên family có sẵn nếu không cùng family; tên tục tĩu
- **Should:** dùng tên phổ biến từ vendor khác; tránh tên địa lý theo nơi phát hiện

### Signature ID và Revision

- `signature id` + `revision` = unique identifier
- `revision` tăng mỗi khi signature được thay thế (fix FP hoặc tăng detection rate)

### Ví dụ

- Win.Trojan.Zusy-9935890-0
- Win.Malware.Agent-9935891-0
- Html.Malware.Agent-9915974-0
- Java.Malware.CVE_2021_44228-9915817-0
- Xls.Downloader.Qbot12211-9916030-0

---

## 18. Target Types và File Types

### 18.1. Target Types

| Type | Mô tả |
|------|-------|
| 0 | Any file |
| 1 | PE (32-bit và 64-bit) |
| 2 | OLE2 containers (MS Office, MSI) |
| 3 | HTML (normalized) |
| 4 | Mail file |
| 5 | Graphics |
| 6 | ELF |
| 7 | ASCII text (normalized) |
| 8 | Unused |
| 9 | Mach-O |
| 10 | PDF |
| 11 | Flash |
| 12 | Java class |

> **Normalization:** HTML, ASCII, Javascript đều được normalize: lowercase, whitespace transform, tag normalization, JS string/number normalization.

### 18.2. File Types (CL_TYPE)

Danh sách CL_TYPE đầy đủ:

| CL_TYPE | Mô tả |
|---------|-------|
| `CL_TYPE_7Z` | 7-Zip Archive |
| `CL_TYPE_7ZSFX` | Self-Extracting 7-Zip |
| `CL_TYPE_ARJ` | ARJ Archive |
| `CL_TYPE_ARJSFX` | Self-Extracting ARJ |
| `CL_TYPE_AUTOIT` | AutoIt Automation Executable |
| `CL_TYPE_BINARY_DATA` | Binary data |
| `CL_TYPE_BINHEX` | BinHex encoding |
| `CL_TYPE_BZ` | BZip Compressed |
| `CL_TYPE_CABSFX` | Self-Extracting CAB |
| `CL_TYPE_CPIO_CRC` | CPIO (CRC) |
| `CL_TYPE_CPIO_NEWC` | CPIO (NEWC) |
| `CL_TYPE_CPIO_ODC` | CPIO (ODC) |
| `CL_TYPE_CPIO_OLD` | CPIO (OLD) |
| `CL_TYPE_CRYPTFF` | CryptFF encrypted |
| `CL_TYPE_DMG` | Apple DMG |
| `CL_TYPE_EGG` | ESTSoft EGG (0.102) |
| `CL_TYPE_ELF` | ELF Executable |
| `CL_TYPE_GIF` | GIF (0.103) |
| `CL_TYPE_GRAPHICS` | BMP, JPEG2000, etc. |
| `CL_TYPE_GZ` | GZip |
| `CL_TYPE_HTML` | HTML |
| `CL_TYPE_HTML_UTF16` | UTF-16 HTML |
| `CL_TYPE_HWP3` | HWP 3.X |
| `CL_TYPE_HWPOLE2` | HWP embedded OLE2 |
| `CL_TYPE_INTERNAL` | Internal properties |
| `CL_TYPE_ISHIELD_MSI` | MSI Installer |
| `CL_TYPE_ISO9660` | ISO 9660 |
| `CL_TYPE_JAVA` | Java Class |
| `CL_TYPE_JPEG` | JPEG (0.103.1) |
| `CL_TYPE_LNK` | Windows Shortcut |
| `CL_TYPE_MACHO` | Mach-O |
| `CL_TYPE_MACHO_UNIBIN` | Universal Binary |
| `CL_TYPE_MAIL` | Email |
| `CL_TYPE_MBR` | MBR Disk Image |
| `CL_TYPE_MHTML` | MHTML Web Page |
| `CL_TYPE_MSCAB` | Microsoft CAB |
| `CL_TYPE_MSCHM` | Microsoft CHM |
| `CL_TYPE_MSEXE` | Microsoft EXE/DLL |
| `CL_TYPE_MSOLE2` | OLE2 Container |
| `CL_TYPE_MSSZDD` | Compressed EXE |
| `CL_TYPE_NULSFT` | NullSoft Installer |
| `CL_TYPE_OLD_TAR` | TAR (old) |
| `CL_TYPE_ONENOTE` | OneNote Section |
| `CL_TYPE_OOXML_HWP` | HWP OOXML |
| `CL_TYPE_OOXML_PPT` | PowerPoint |
| `CL_TYPE_OOXML_WORD` | Word 2007+ |
| `CL_TYPE_OOXML_XL` | Excel 2007+ |
| `CL_TYPE_PART_HFSPLUS` | HFS+ Partition |
| `CL_TYPE_PDF` | PDF |
| `CL_TYPE_PNG` | PNG (0.103) |
| `CL_TYPE_POSIX_TAR` | TAR |
| `CL_TYPE_PS` | Postscript |
| `CL_TYPE_PYTHON_COMPILED` | Python .pyc |
| `CL_TYPE_RAR` | RAR |
| `CL_TYPE_RARSFX` | Self-Extracting RAR |
| `CL_TYPE_RIFF` | RIFF |
| `CL_TYPE_RTF` | Rich Text Format |
| `CL_TYPE_SCRENC` | ScrEnc encrypted |
| `CL_TYPE_SCRIPT` | Generic script (JS, Python, ...) |
| `CL_TYPE_SIS` | Symbian SIS |
| `CL_TYPE_SWF` | Adobe Flash |
| `CL_TYPE_TEXT_ASCII` | ASCII text |
| `CL_TYPE_TEXT_UTF16BE` | UTF-16BE text |
| `CL_TYPE_TEXT_UTF16LE` | UTF-16LE text |
| `CL_TYPE_TEXT_UTF8` | UTF-8 text |
| `CL_TYPE_TIFF` | TIFF (0.103.1) |
| `CL_TYPE_TNEF` | MS TNEF |
| `CL_TYPE_UDF` | UDF Partition |
| `CL_TYPE_UUENCODED` | UUEncoded |
| `CL_TYPE_XAR` | XAR Archive |
| `CL_TYPE_XDP` | Adobe XDP |
| `CL_TYPE_XML_HWP` | HWP XML |
| `CL_TYPE_XML_WORD` | Word 2003 XML |
| `CL_TYPE_XML_XL` | Excel 2003 XML |
| `CL_TYPE_XZ` | XZ Archive |
| `CL_TYPE_ZIP` | Zip |
| `CL_TYPE_ZIPSFX` | Self-Extracting Zip |
| `CL_TYPE_APM` | Apple Partition Map |
| `CL_TYPE_GPT` | GUID Partition Table |

---

## 19. Signature Writing Tips and Tricks

### 19.1. Testing với clamscan

```bash
clamscan -d test.ldb test.exe
```

Nếu signature sai format, chạy với `--debug --verbose` để xem lỗi.

Nếu không match:
- Tăng scan limits: `--max-filesize=2000M --max-scansize=2000M --max-files=2000000 ...`
- Kiểm tra normalization (HTML/text)
- Kiểm tra debug output xem file có được unpack không

> **Lưu ý:** `clamscan -d` không load signatures từ freshclam. Cần thêm `-d` riêng cho CVD files nếu cần unpacker/bytecode.

### 19.2. Debug từ libclamav

```bash
clamscan --debug --leave-temps attachment.exe
```

Công dụng:
- Xem ClamAV nhận diện file như thế nào (PE, ELF, packed, ...)
- Xem unpacked executable được lưu ở đâu (thường `/tmp/clamav-*`)
- Tạo signature cho decompressed file → generic hơn, bao phủ nhiều packer hơn

### 19.3. HTML Normalization

```bash
sigtool --html-normalise file.html
```

Tạo ra:
- `nocomment.html` – lowercase, bỏ comments/whitespace thừa
- `notags.html` – như trên, bỏ HTML tags
- `javascript` – JS normalized

Signature cho normalized HTML nên dùng target type 3.

### 19.4. Text Files Normalization

```bash
sigtool --ascii-normalise file.txt
```

Tạo ra `normalised_text`. Signature cho normalized ASCII text nên dùng target type 7.

### 19.5. Các sigtool flags hữu ích

| Flag | Công dụng |
|------|-----------|
| `--md5` / `--sha1` / `--sha256` | Tạo hash signatures |
| `--mdb` | Tạo PE section hash signatures |
| `--imp` | Tạo PE import table hash signatures |
| `--decode` | Decode signature thành dạng dễ đọc (`cat test.ldb \| sigtool --decode`) |
| `--hex-dump` | Chuyển bytes → hex string |
| `--html-normalise` | Normalize HTML |
| `--ascii-normalise` | Normalize ASCII text |
| `--print-certs` | In Authenticode signatures của PE files |
| `--vba` | Extract VBA/Word6 macro code |
| `--test-sigs` | Test signature match và hiển thị offset |

### 19.6. Inspect CVD files

```bash
sigtool -i main.cvd
sigtool --unpack /var/lib/clamav/main.cvd
```

CVD header (512 bytes, colon-separated):
```
ClamAV-VDB:build time:version:number of signatures:functionality level required:MD5 checksum:digital signature:builder name:build time (sec)
```

### 19.7. External Tools

- [CASC](https://github.com/Cisco-Talos/CASC) – IDA Pro plugin để tạo signature từ highlighted code, kèm SigAlyzer để phân tích signature match.

---

## 20. CVD Header Format

CVD header là string 512 bytes với các trường cách nhau bởi dấu hai chấm:

```
ClamAV-VDB:build time:version:number of signatures:functionality level required:MD5 checksum:digital signature:builder name:build time (sec)
```

---

## 21. FLEVEL Reference

FLEVEL (Functionality Level) là số nguyên xác định phiên bản engine tối thiểu cần thiết để xử lý một signature. Dùng trong `Engine:X-Y` của Logical Signatures, `min_flevel`/`max_flevel` của Extended Signatures, DCONF, và nhiều format khác.

| FLEVEL | ClamAV Version |
|--------|----------------|
| 51 | 0.96 |
| 73 | 0.98 |
| 81 | 0.99 |
| 90 | 0.100 |
| 150 | 0.105 |
| 255 | Future/compat |

---

> **Tài liệu tham khảo:** https://docs.clamav.net/manual/Signatures.html
