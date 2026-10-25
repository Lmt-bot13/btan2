# BÀI TẬP: AN TOÀN VÀ BẢO MẬT THÔNG TIN


**Sinh viên:** Lưu Minh Trí

**Mã số sinh viên:** K235480106104

**Lớp:** K59.KTP.K01

## Chuẩn bị môi trường

**Yêu cầu:** Windows 10/11 và .NET 10 SDK và Visual Studio 2026.

Ứng dụng dùng Windows Forms nên chỉ chạy trên Windows. Mỗi bài là **một dự án gồm đúng 2 file**: tệp `.csproj` và `Program.cs`. 

Cài đặt visual studio:

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/3a2b8d44-5157-456b-b797-af8c351a7690" />


Khởi tạo project 

<img width="1917" height="1077" alt="h1" src="https://github.com/user-attachments/assets/03f473df-70bc-4311-b72c-1a042acb4b81" />

<img width="1917" height="1077" alt="h2" src="https://github.com/user-attachments/assets/ad3a0d7f-bd29-46ef-ab09-fe74a08453d0" />


# BÀI 1 — MÃ HOÁ AES

> **Đề bài:** Mã hoá đối xứng (mã hoá và giải mã dùng cùng một khoá). Tạo ứng dụng (không phải web): sinh khoá, lưu khoá ra file, nạp khoá từ file, mã hoá văn bản, mã hoá file. Thử nghiệm với file hàng GB, tính thời gian mã hoá / giải mã, so sánh theo byte file nguồn và file giải mã, rồi kết luận dựa trên số liệu.

## 1.1 Phân tích từng yêu cầu

### Yêu cầu 1 — Sinh khoá AES

**Bản chất:** AES là mật mã khối, mỗi khối 128 bit, khoá dài 128, 192 hoặc 256 bit (16, 24 hoặc 32 byte). Độ an toàn của hệ thống nằm ở khoá, nên khoá phải **ngẫu nhiên không đoán được**.

**Quyết định thiết kế:**

- Dùng bộ sinh số ngẫu nhiên an toàn mật mã `RandomNumberGenerator` (không dùng `System.Random` vì dự đoán được).

- Mặc định chọn **AES-256** (32 byte), cho phép chọn 128 / 192 / 256 bit trên giao diện.

- Chế độ hoạt động **CBC** có padding **PKCS7**. Chế độ này cần thêm **vector khởi tạo IV** dài 16 byte. IV không cần giữ bí mật nhưng phải **ngẫu nhiên và khác nhau ở mỗi lần mã hoá**, nên IV được sinh mới mỗi lần và lưu kèm bản mã.

**Kết quả cần có:** một mảng byte khoá hiển thị dạng Base64 và "vân tay" SHA-256 (16 ký tự hex đầu) để nhận diện khoá mà không lộ khoá.

Sinh khóa

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/5f81b6d2-2c65-4808-a095-193e45fac154" />


### Yêu cầu 2 — Lưu khoá ra file

**Phân tích:** khoá là dữ liệu nhị phân, ghi thẳng vào file văn bản sẽ hỏng ký tự. Giải pháp là mã hoá **Base64** rồi ghi ra file `*.key`. File này dễ mở, dễ sao chép, dễ kiểm tra bằng mắt.

**Lưu ý bảo mật:** file khoá chính là "chìa khoá" của hệ thống. Không đưa lên Git, không gửi qua kênh công khai.

Lưu ra 1 file 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6538a2a6-e508-43a9-ac9a-b29ae2a87695" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/22623b9d-850d-43b6-8715-194f8f8ea97e" />

### Yêu cầu 3 — Nhập khoá từ file

**Phân tích:** đọc chuỗi Base64, giải mã về byte, rồi **kiểm tra độ dài hợp lệ** (16 / 24 / 32 byte). Nếu sai độ dài hoặc không phải Base64 thì báo lỗi rõ ràng thay vì để thuật toán văng ngoại lệ khó hiểu.

Nạp khóa từ file 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/81d555dc-836c-4b67-9db1-06689138886a" />

<img width="1912" height="1077" alt="image" src="https://github.com/user-attachments/assets/518d5eb7-b452-4dbc-8dc1-3d34c82521a0" />


### Yêu cầu 4 — Mã hoá một đoạn văn bản, kết quả ra màn hình

**Luồng xử lý:**

1. Văn bản → mảng byte theo **UTF-8** (hỗ trợ tiếng Việt có dấu).

2. Sinh IV ngẫu nhiên 16 byte.

3. Mã hoá AES-CBC-PKCS7.

4. Ghép `IV ‖ bản mã` rồi chuyển **Base64** để hiển thị.

**Giải mã:** làm ngược lại — tách 16 byte đầu làm IV, phần còn lại là bản mã.

**Hệ quả quan trọng:** vì IV khác nhau mỗi lần, **cùng một văn bản mã hoá hai lần cho hai kết quả khác nhau**, nhưng đều giải mã đúng. Đây là tính chất mong muốn, không phải lỗi.


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6587df60-af2e-4a2d-aeb5-14474c65236a" />

Mã hóa văn bản

### Yêu cầu 5 — Mã hoá một file và lưu ra file

**Vấn đề với file hàng GB:** nếu đọc cả file vào RAM (`File.ReadAllBytes`) sẽ tràn bộ nhớ, và mảng trong .NET bị giới hạn khoảng 2 GB.

**Giải pháp: xử lý dạng luồng (streaming).**

- Đọc từng khối **1 MiB**, đưa qua `CryptoStream`, ghi ra file đích.

- Mức RAM sử dụng gần như **không đổi** dù file 1 GB hay 100 GB.

- Chạy trên luồng nền (`Task.Run`) và báo tiến độ qua `ProgressBar` để giao diện không bị treo.

**Định dạng file `.enc`:**

| Vị trí | Độ dài | Nội dung |
|---|---|---|
| 0 – 15 | 16 byte | IV (ngẫu nhiên, ghi rõ ở đầu file) |
| 16 – hết | n + (1…16) byte | Bản mã AES-CBC (có padding PKCS7) |

Do padding nên file `.enc` luôn lớn hơn file gốc từ 17 đến 32 byte.

Tạo file nguồn 

<img width="1915" height="1078" alt="image" src="https://github.com/user-attachments/assets/219b1f15-8d7b-414e-a3da-3d04165e1560" />

Mã hóa file nguồn tự và lưu vào file đích 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/8873a8db-ce29-4c59-84a8-3adca0a96ecb" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/5d8fbc29-8c1c-40d8-a48d-cafe57382e53" />


### Thử nghiệm file hàng GB, đo thời gian, so sánh byte

**a) Tạo file lớn để thử:** thêm nút **"Tạo tệp thử nghiệm"** sinh file ngẫu nhiên có kích thước tuỳ chọn (ví dụ 1024 MB = 1 GB), vì không phải máy nào cũng có sẵn file hàng GB.

**b) Tính thời gian:** dùng `Stopwatch` bao quanh đúng phần mã hoá và đúng phần giải mã. Quy đổi ra **MB/s** để so sánh công bằng giữa các kích thước.

**c) So sánh theo byte:** đọc song song hai file theo từng khối 1 MiB, so khối bằng `CommonPrefixLength`. Kết quả:

- Nếu khác độ dài → khác ngay.

- Nếu có byte lệch → báo **vị trí byte lệch đầu tiên**.

- Nếu giống hết → xác nhận "giống hệt từng byte".

Thử nghiệm các file với dung lượng khác nhau 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/89e08f2e-2f29-4650-a06a-6fe8b4b6359b" />


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/e29a0103-752c-40b9-8654-7195be304939" />


| Kích thước (MB) | Mã hoá (s) | Giải mã (s) | Tốc độ mã hoá (MB/s) | Tốc độ giải mã (MB/s) | So sánh byte (s) | Kết quả |
|---:|---:|---:|---:|---:|---:|---|
| 256 | 0,43 | 0,24 | 602 | 1085 | 0,09 | Khớp 100% |
| 1024 | 2,28 | 1,65 | 449 | 619 | 0,44 | Khớp 100% |
| 2048 | 3,31 | 1,60 | 618 | 1279 | 1,83 | Khớp 100% |

### Kết luận 

**Kết luận 1 — Tính đúng đắn.** Ở mọi kích thước thử nghiệm, so sánh từng byte cho kết quả "giống hệt". Vậy quy trình `mã hoá → giải mã` là **khả nghịch hoàn toàn**, không mất và không sai lệch dữ liệu, kể cả với file lớn hơn 1 GB.

**Kết luận 2 — Thời gian tăng gần tuyến tính theo kích thước.** AES-CBC xử lý mỗi khối 16 byte với chi phí như nhau nên độ phức tạp là **O(n)**. Cỡ file tăng bao nhiêu lần thì thời gian tăng xấp xỉ bấy nhiêu lần, còn tốc độ MB/s gần như ổn định. Nếu số liệu của bạn lệch nhiều thì nguyên nhân thường là bộ nhớ đệm của hệ điều hành và tốc độ ổ đĩa.

**Kết luận 3 — Giải mã thường nhanh hơn hoặc bằng mã hoá.** Chế độ CBC khi mã hoá phải làm **tuần tự** (khối sau phụ thuộc khối trước), còn khi giải mã mỗi khối chỉ phụ thuộc bản mã có sẵn nên CPU xử lý song song được nhờ tập lệnh **AES-NI**. Số liệu mẫu ở trên cũng cho thấy giải mã nhanh hơn rõ rệt.

**Kết luận 4 — Nút thắt thường là ổ đĩa, không phải thuật toán.** Tốc độ vài trăm đến hơn một nghìn MB/s cho thấy bản thân AES rất nhanh nhờ phần cứng. Khi dữ liệu đạt cỡ GB thì tốc độ đọc/ghi đĩa quyết định tổng thời gian. Vì vậy cách làm **streaming với bộ đệm 1 MiB** vừa giữ RAM cố định vừa tận dụng được đường truyền I/O.

**Kết luận 5 — Chi phí so sánh byte nhỏ hơn mã hoá.** So sánh chỉ đọc hai file, không tính toán mật mã, nên nhanh hơn nhiều. Đây là cách kiểm chứng toàn vẹn rẻ và chắc chắn.

**Kết luận 6 — Về thiết kế.** Dùng khoá ngẫu nhiên CSPRNG, IV mới cho mỗi lần mã hoá, ghi IV ở đầu file giúp chương trình an toàn và tự mô tả. Hạn chế: CBC **không có xác thực** (không phát hiện file mã hoá bị sửa). Với hệ thống thực tế nên dùng **AES-GCM** hoặc thêm HMAC.

---

# BÀI 2 — MÃ HOÁ RSA, SHA-256, CHỮ KÝ SỐ

> **Đề bài:** Mã hoá bất đối xứng (mã hoá bằng một khoá, giải mã bằng khoá còn lại). Tạo ứng dụng .NET gồm 9 yêu cầu: sinh cặp khoá, xuất PEM, xem PEM cùng ý nghĩa từng byte, nhập PEM để lấy n/e/d…, mã hoá dữ liệu ≤ 190 byte, giải mã và so sánh, đánh giá tốc độ (khoá công khai so với khoá riêng), băm SHA-256 và đánh giá thay đổi, chữ ký số và đề xuất phương pháp để cùng dữ liệu, cùng người ký nhưng chữ ký khác nhau.

Tạo project 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/2e9ec063-3178-4086-bd48-5f40c64eb3c1" />

## 2.1 Phân tích từng yêu cầu

### Yêu cầu 1 — Sinh cặp khoá

**Nguyên lý RSA:**

1. Chọn hai số nguyên tố lớn $p$, $q$ → $n = p \cdot q$.

2. Tính $\varphi(n) = (p-1)(q-1)$.

3. Chọn số mũ công khai $e$ (thường $e = 65537 = 2^{16}+1$, chỉ 17 bit).

4. Tính số mũ bí mật $d = e^{-1} \bmod \varphi(n)$.

5. **Khoá công khai** là $(n, e)$. **Khoá bí mật** là $(n, d)$, kèm $p, q, d_P, d_Q, q_{inv}$ để tăng tốc bằng định lý số dư Trung Hoa (CRT).

**Quyết định thiết kế:** dùng `RSA.Create(bits)` với 1024 / 2048 / 3072 / 4096 bit, mặc định **2048 bit** (đủ an toàn và khớp với giới hạn 190 byte của yêu cầu 5). Việc sinh khoá chạy luồng nền vì khoá lớn có thể mất vài giây.

Sinh 1 cặp khóa 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/4792bc4e-386e-4072-ab7a-26646b93554c" />


### Yêu cầu 2 — Xuất cặp khoá ra file PEM

**PEM** là Base64 của dữ liệu **DER (ASN.1)**, bọc giữa dòng `-----BEGIN …-----` và `-----END …-----`, mỗi dòng 64 ký tự.

| Loại khoá | Chuẩn | Dòng mở đầu | Hàm .NET |
|---|---|---|---|
| Công khai | X.509 SubjectPublicKeyInfo | `-----BEGIN PUBLIC KEY-----` | `ExportSubjectPublicKeyInfoPem()` |
| Bí mật | PKCS#8 | `-----BEGIN PRIVATE KEY-----` | `ExportPkcs8PrivateKeyPem()` |

Ứng dụng có hai khung riêng (public / private) và nút **Lưu .pem** cho từng khung. Trước khi lưu, chương trình nạp thử PEM để chắc chắn nội dung hợp lệ.

Lưu khóa vào pem 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f65b9c47-c9ed-4dec-b549-923692ba27a9" />


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/e2d71b19-1928-4125-8f64-ddf83282ab75" />

### Yêu cầu 3 — Xem PEM và ý nghĩa các byte

**Quy tắc mã hoá DER:** mọi phần tử đều có dạng **TLV**.

| Thành phần | Độ dài | Ý nghĩa |
|---|---|---|
| **T**ag | 1 byte | Loại dữ liệu: `30` SEQUENCE, `02` INTEGER, `03` BIT STRING, `04` OCTET STRING, `05` NULL, `06` OID |
| **L**ength | 1–5 byte | Nếu < 128: 1 byte. Nếu ≥ 128: byte `8N` rồi N byte độ dài (ví dụ `82 01 22` = 0x0122 = 290) |
| **V**alue | L byte | Nội dung; với SEQUENCE thì chính là các phần tử TLV lồng bên trong |

**Giải phẫu khoá công khai RSA-2048 (294 byte DER, đã kiểm chứng bằng chính ứng dụng):**

| Offset | Byte (hex) | Ý nghĩa |
|---:|---|---|
| 0 | `30 82 01 22` | SEQUENCE ngoài cùng, dài 290 byte |
| 4 | `30 0D` | SEQUENCE `AlgorithmIdentifier`, dài 13 byte |
| 6 | `06 09 2A 86 48 86 F7 0D 01 01 01` | OID `1.2.840.113549.1.1.1` = **rsaEncryption** |
| 17 | `05 00` | NULL: thuật toán không có tham số |
| 19 | `03 82 01 0F 00` | BIT STRING dài 271 byte; byte `00` = không có bit thừa |
| 24 | `30 82 01 0A` | SEQUENCE `RSAPublicKey`, dài 266 byte |
| 28 | `02 82 01 01 00 A3 C8 …` | INTEGER dài 257 byte = **n** (byte `00` đầu để số luôn dương, còn lại 256 byte = 2048 bit) |
| 289 | `02 03 01 00 01` | INTEGER dài 3 byte = **e = 0x010001 = 65537** |

**Kiểm tra số học:** 15 (thuật toán) + 4 + 271 (bit string) = 290 ✔. Bên trong bit string: 1 + 4 + 266 = 271 ✔. Bên trong `RSAPublicKey`: 261 (n) + 5 (e) = 266 ✔.

**Mẹo nhận biết bằng mắt:** `30 82` mã hoá Base64 thành `MII`, nên mọi khoá RSA 2048 bit đều bắt đầu bằng `MIIB…` (công khai) hoặc `MIIE…` (bí mật).

**Khoá bí mật PKCS#8** có cấu trúc lồng:

```text
SEQUENCE
 ├─ INTEGER 0                       (version)
 ├─ SEQUENCE { OID rsaEncryption, NULL }
 └─ OCTET STRING                    (bọc RSAPrivateKey)
     └─ SEQUENCE
         ├─ INTEGER 0               (version)
         ├─ INTEGER n               (modulus)
         ├─ INTEGER e               (publicExponent)
         ├─ INTEGER d               (privateExponent)
         ├─ INTEGER p
         ├─ INTEGER q
         ├─ INTEGER dP = d mod (p-1)
         ├─ INTEGER dQ = d mod (q-1)
         └─ INTEGER qInv = q^-1 mod p
```


**Giải pháp trong ứng dụng:** nút **Phân tích** tự giải Base64, đi qua cây ASN.1 và in từng dòng: vị trí, các byte Tag + Length (hex), tên loại, độ dài và nhãn ý nghĩa (`◄ n`, `◄ e`, `◄ d`…).
Dịch nghĩa trong pem


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f0700be2-866b-49a4-9e59-3acca452ddd9" />


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/e6eab03c-9883-4526-8ab1-0a370086c42e" />


### Yêu cầu 4 — Nhập PEM để lấy n, e (công khai) và n, e, d, … (bí mật)

**Cách làm:** `RSA.ImportFromPem(pem)` rồi `ExportParameters(includePrivate)` trả về các trường `Modulus` (n), `Exponent` (e), `D`, `P`, `Q`, `DP`, `DQ`, `InverseQ`.

**Chốt chặn đúng sai:** đưa nhầm private vào khung public (và ngược lại) sẽ báo lỗi rõ ràng. Với khoá bí mật, chương trình kiểm tra thêm **p·q = n** để chứng minh khoá nhập vào nhất quán.

Số lớn được in dạng hex, xuống dòng mỗi 64 ký tự, kèm số bit (ví dụ n = 2048 bit, e = 17 bit, d ≈ 2048 bit).

Tham số n e trong public key


<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/a94cea20-f9e7-4c69-8542-a9951c5dc063" />

Tham số n, e, d , q, p trong private key 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/906b53da-9f80-45d2-8c1b-555ed0e11673" />


### Yêu cầu 5 — Mã hoá dữ liệu (mảng byte không quá 190 byte) bằng khoá vừa nhập

**Vì sao đúng 190 byte?** Dùng đệm **RSA-OAEP với SHA-256**. Dữ liệu tối đa là:

$$ k - 2 \cdot hLen - 2 = 256 - 2 \cdot 32 - 2 = 190 \text{ byte} $$

(với $k = 256$ byte là độ dài modulus 2048 bit, $hLen = 32$ byte là độ dài SHA-256).

Con số 190 byte hoàn toàn đủ để mã hoá **một khoá AES-256 (32 byte)**. Đây chính là nguyên tắc **mã hoá lai (hybrid)**: dữ liệu lớn mã hoá bằng AES, khoá AES mã hoá bằng RSA.

**Thiết kế đầu vào:** ô nhập có hai chế độ:

- Văn bản UTF-8 thông thường.

- Tích chọn **Base64** để nhập một mảng byte (ví dụ khoá AES). Có nút **Sinh khoá AES-256 ngẫu nhiên (32 byte)** điền sẵn.

Nhãn độ dài báo xanh khi 1…190 byte, báo đỏ khi vượt.

**Kết quả:** mảng byte bản mã (256 byte) → Base64 → lưu file văn bản.

Mã hóa 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/d6a176ab-5c34-4616-9f74-148072de83b5" />


### Yêu cầu 6 — Giải mã và so sánh với nguồn

**Đầu vào:** file PEM (private key) và file chứa bản mã Base64.

**Quy trình:** nạp PEM → Base64 → byte → `Decrypt(…, OaepSHA256)` → hiển thị cả dạng Base64 và UTF-8.

**So sánh:** dùng `SequenceEqual` giữa dữ liệu sau giải mã và dữ liệu gốc ở ô nhập. Hiển thị **✔ GIỐNG HỆT** hoặc **✘ KHÁC**.

Nếu để trống đường dẫn PEM thì dùng khoá bí mật đang nạp trong ứng dụng.

 Giải mã kiểm tra dữ liệu nguồn 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/7706703e-54ed-420c-8767-7d732cc8c8bf" />


### Yêu cầu 7 — Đánh giá tốc độ mã hoá / giải mã (khoá công khai so với khoá riêng)

**Giả thuyết cần kiểm chứng:** mã hoá dùng $c = m^e \bmod n$ với $e = 65537$ chỉ 17 bit, còn giải mã dùng $m = c^d \bmod n$ với $d$ cỡ 2048 bit. Phép luỹ thừa mô-đun cần xấp xỉ **một phép bình phương cho mỗi bit của số mũ**, nên:

- Số mũ công khai: khoảng 17 bình phương + 2 phép nhân.

- Số mũ bí mật: khoảng 2048 bình phương + ~1024 phép nhân.

Tỉ lệ lý thuyết là cỡ **100–170 lần** nếu không tối ưu.

**Thực tế phức tạp hơn một chút:** thư viện thật dùng CRT, tách phép tính thành hai luỹ thừa 1024 bit nên nhanh hơn khoảng 3–4 lần. Vì thế ứng dụng đo **ba nhóm** để thấy rõ cả hai hiện tượng:

| Nhóm | Phép đo | Mục đích |
|---|---|---|
| A | RSA-OAEP: mã hoá (public) và giải mã (private) | Hiệu năng thực tế của .NET |
| B | Chữ ký PKCS#1: xác minh (public) và ký (private) | Cùng quy luật cho chữ ký số |
| C | `BigInteger.ModPow` với e và với d (không CRT) | Cho thấy thuần tuý ảnh hưởng độ dài số mũ |

Mỗi phép đo có bước khởi động (loại bỏ chi phí JIT), lặp N lần (mặc định 100) và lấy trung bình bằng `Stopwatch`. Kết quả hiển thị ms/lần, số lần/giây và **thanh ngang** biểu diễn tương quan.

Đánh giá và đo tốc độ 


<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/c8a04bc9-1b96-40b1-8c5f-34fe767dd82f" />


### Yêu cầu 8 — Băm SHA-256 và đánh giá thay đổi khi đầu vào đổi rất ít

**SHA-256:** nhận dữ liệu bất kỳ, trả về **256 bit (32 byte, 64 ký tự hex)**.

**Tính chất cần chứng minh bằng thực nghiệm — hiệu ứng tuyết lở (avalanche):** đổi một bit đầu vào thì khoảng **50%** số bit đầu ra bị đổi (≈ 128 / 256 bit), và vị trí đổi không thể dự đoán.

**Giải pháp giao diện:**

- Ô nhập tự băm lại sau **mỗi ký tự gõ**.

- Hiển thị hash trước đó và hash hiện tại, các ký tự hex khác nhau được tô **màu cam**.

- Tính **khoảng cách Hamming** giữa hai hash (số bit khác nhau) bằng `PopCount(a XOR b)` và hiển thị dạng "131/256 bit (51,2%)".

- **Lưới 16×16** vẽ đủ 256 bit; bit đã đổi có viền cam, người xem thấy ngay đổi rải đều.

- Hiển thị **trung bình** sau nhiều lần sửa; số liệu hội tụ về ≈ 50%.

- Ba nút thao tác nhanh: đổi ký tự cuối, thêm dấu cách, xoá ký tự cuối.

Băm bằng đổi ký tự cuối


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/fe888263-c47a-47fe-b602-0877935e0133" />

Thêm 1 dấu cách 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/96662aa6-f90d-4a79-8ef0-635f2b3430df" />

Xóa ký tự cuối


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/570c1dc7-d677-4262-9edc-5757bf7b584f" />


### Yêu cầu 9 — Chữ ký số và đề xuất phương pháp để mỗi lần ký cho một chữ ký khác nhau

**Chữ ký số:** băm dữ liệu bằng SHA-256, rồi dùng RSA với **khoá bí mật** trên giá trị băm → chữ ký. Người nhận dùng **khoá công khai** xác minh. Dữ liệu khác nhau cho chữ ký khác nhau.

**Vấn đề:** chữ ký chuẩn **PKCS#1 v1.5** là thuật toán **xác định (deterministic)**. Cùng dữ liệu + cùng khoá luôn cho đúng một chữ ký, nên kẻ quan sát biết "thông điệp này đã được ký lại", không thể phân biệt hai lần ký riêng biệt.

**Mong muốn:** cùng dữ liệu, cùng private key, mỗi lần ký cho chữ ký **khác nhau** nhưng **đều xác minh hợp lệ**.

**Nguyên tắc chung của mọi đề xuất:** đưa một **giá trị ngẫu nhiên** vào trong quá trình ký, và để người xác minh biết cách khôi phục / kiểm tra giá trị đó.

| Phương pháp | Cách làm | Ưu điểm | Nhược điểm |
|---|---|---|---|
| **A. PKCS#1 v1.5** (đối chứng) | `EM = 00 01 FF…FF 00 ‖ DigestInfo`, không có ngẫu nhiên | Đơn giản, phổ biến | **Luôn cho chữ ký giống nhau** → không đạt yêu cầu |
| **B. RSA-PSS (đề xuất chính)** | Sinh **salt ngẫu nhiên** 32 byte, `H = SHA256(0⁸ ‖ mHash ‖ salt)`, rồi che salt bằng MGF1 và nhúng vào khối được ký | Là **chuẩn** (PKCS#1 v2.1 / RFC 8017), có chứng minh an toàn chặt chẽ, người xác minh tự khôi phục salt từ chữ ký, không cần gửi thêm gì | Cần thư viện hỗ trợ (.NET có sẵn `RSASignaturePadding.Pss`) |
| **C. Nonce ‖ dữ liệu** (ngẫu nhiên hoá băm) | Sinh nonce 16 byte, ký `SHA256(nonce ‖ dữ liệu)` bằng PKCS#1, gửi kèm `nonce.chữ_ký` | Tự cài đặt được trên mọi thư viện, minh hoạ rõ nguyên lý | Phải gửi thêm nonce, định dạng riêng, không phải chuẩn |
| D. Thêm thời gian / số thứ tự vào dữ liệu | Ký `dữ liệu ‖ timestamp` | Chống phát lại (replay) | Làm thay đổi **dữ liệu** được ký, không còn là "cùng một dữ liệu" |

**Kết luận đề xuất:** dùng **RSA-PSS** (phương pháp B). Đây là phương pháp chuẩn mực, vừa **đạt đúng mong muốn** (mỗi lần ký khác nhau) vừa **không giảm độ an toàn** (thực tế an toàn hơn PKCS#1 v1.5 nhờ chứng minh an toàn). Phương pháp C là phương án dự phòng, dùng để minh hoạ nguyên lý.

**Cách ứng dụng thể hiện:** bấm một nút, mỗi phương pháp ký **5 lần** cùng một dữ liệu, rồi:

- Đếm số chữ ký **khác nhau** trên 5 (A sẽ là 1/5, B và C là 5/5).

- Xác minh từng chữ ký với **dữ liệu gốc** (phải hợp lệ).

- Xác minh với **dữ liệu bị đổi 1 bit** (phải bị từ chối).

Ký chữ ký số 


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/446f22a8-6949-4c74-9ada-1a41097b7468" />


Tốc độ RSA-2048 


| Phép đo | Khoá | Số mũ | Thời gian (ms/lần) | Lần/giây |
|---|---|---|---:|---:|
| RSA-OAEP mã hoá | Public | e = 65537 (17 bit) | 0,0196 | 51 020 |
| RSA-OAEP giải mã | Private | d ≈ 2041 bit (có CRT) | 0,2557 | 3 911 |
| Chữ ký PKCS#1 — xác minh | Public | e (17 bit) | 0,0199 | 50 188 |
| Chữ ký PKCS#1 — ký | Private | d (có CRT) | 0,2716 | 3 682 |
| `ModPow` m^e mod n | — | 17 bit | 0,1541 | — |
| `ModPow` m^d mod n (không CRT) | — | 2041 bit | 26,8678 | — |


###  Chữ ký số: số chữ ký khác nhau khi ký 5 lần cùng dữ liệu (kết quả kiểm chứng)

| Phương pháp | Chữ ký khác nhau / 5 | Xác minh dữ liệu gốc | Xác minh dữ liệu bị đổi 1 bit | Đạt yêu cầu? |
|---|:---:|:---:|:---:|:---:|
| A. PKCS#1 v1.5 | **1** / 5 | ✔ | ✘ (bị từ chối) | **Không** |
| B. RSA-PSS | **5** / 5 | ✔ | ✘ (bị từ chối) | **Có** |
| C. Nonce ‖ dữ liệu | **5** / 5 | ✔ | ✘ (bị từ chối) | **Có** |

### Kết luận 

**Kết luận 1 — Mã hoá RSA đúng và khả nghịch.** Dữ liệu 32 byte (khoá AES-256) mã hoá bằng public key rồi giải mã bằng private key cho kết quả giống hệt nguồn khi so sánh từng byte. Ngưỡng **190 byte** được kiểm chứng: 190 byte mã hoá được (bản mã 256 byte), 191 byte bị từ chối.

**Kết luận 2 — Khoá công khai (e nhỏ) nhanh hơn khoá bí mật (d lớn) rõ rệt.** Với số liệu mẫu, giải mã chậm hơn mã hoá khoảng **13 lần** (có CRT) và ký chậm hơn xác minh khoảng **13,6 lần**. Ở phép tính thô không CRT, số mũ d chậm hơn e khoảng **174 lần**, rất sát tỉ lệ số bit của số mũ (2041 / 17 ≈ 120, cộng thêm các phép nhân). Nguyên nhân: chi phí luỹ thừa mô-đun tỉ lệ với **số bit của số mũ**.

**Kết luận 3 — CRT thu hẹp khoảng cách nhưng không xoá được.** Từ 174 lần xuống còn khoảng 13 lần nhờ CRT (tách thành hai phép toán 1024 bit). Điều này cũng giải thích vì sao khoá bí mật lưu thêm p, q, dP, dQ, qInv.

**Kết luận 4 — Thiết kế này phù hợp thực tế.** Hệ thống có rất nhiều người **xác minh / mã hoá** (dùng public key, nhanh) nhưng chỉ một chủ khoá **ký / giải mã** (dùng private key, chậm hơn nhưng ít lần). Cặp tốc độ bất đối xứng này có lợi cho kiến trúc máy chủ – nhiều máy khách.

**Kết luận 5 — RSA chậm hơn AES rất nhiều lần nên chỉ dùng cho dữ liệu nhỏ.** Do đó mô hình đúng là **lai**: AES mã hoá dữ liệu lớn (Bài 1, hàng trăm MB/s), RSA chỉ mã hoá khoá AES 32 byte.

**Kết luận 6 — SHA-256 có hiệu ứng tuyết lở.** Sửa một ký tự đầu vào làm thay đổi trung bình xấp xỉ 50% (cỡ 128/256) bit đầu ra, đổi rải đều trên lưới, không có quy luật. Vì vậy từ hash không suy ra được dữ liệu và hai dữ liệu gần giống nhau cho hash hoàn toàn khác nhau; đó là lý do chữ ký trên hash phát hiện được mọi sửa đổi.

**Kết luận 7 — Đề xuất phương pháp chữ ký ngẫu nhiên.** PKCS#1 v1.5 xác định nên chỉ cho 1/5 chữ ký khác nhau. **RSA-PSS** thêm salt ngẫu nhiên nên cho 5/5 chữ ký khác nhau mà vẫn xác minh đúng; dữ liệu bị sửa dù 1 bit đều bị từ chối. Vì vậy đề xuất dùng **RSA-PSS** (chuẩn, an toàn chứng minh được); phương án **nonce ‖ dữ liệu** đạt cùng hiệu quả nhưng phải gửi thêm nonce và dùng định dạng riêng.
