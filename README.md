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

### Yêu cầu 2 — Lưu khoá ra file

**Phân tích:** khoá là dữ liệu nhị phân, ghi thẳng vào file văn bản sẽ hỏng ký tự. Giải pháp là mã hoá **Base64** rồi ghi ra file `*.key`. File này dễ mở, dễ sao chép, dễ kiểm tra bằng mắt.

**Lưu ý bảo mật:** file khoá chính là "chìa khoá" của hệ thống. Không đưa lên Git, không gửi qua kênh công khai.

### Yêu cầu 3 — Nhập khoá từ file

**Phân tích:** đọc chuỗi Base64, giải mã về byte, rồi **kiểm tra độ dài hợp lệ** (16 / 24 / 32 byte). Nếu sai độ dài hoặc không phải Base64 thì báo lỗi rõ ràng thay vì để thuật toán văng ngoại lệ khó hiểu.

### Yêu cầu 4 — Mã hoá một đoạn văn bản, kết quả ra màn hình

**Luồng xử lý:**

1. Văn bản → mảng byte theo **UTF-8** (hỗ trợ tiếng Việt có dấu).

2. Sinh IV ngẫu nhiên 16 byte.

3. Mã hoá AES-CBC-PKCS7.

4. Ghép `IV ‖ bản mã` rồi chuyển **Base64** để hiển thị.

**Giải mã:** làm ngược lại — tách 16 byte đầu làm IV, phần còn lại là bản mã.

**Hệ quả quan trọng:** vì IV khác nhau mỗi lần, **cùng một văn bản mã hoá hai lần cho hai kết quả khác nhau**, nhưng đều giải mã đúng. Đây là tính chất mong muốn, không phải lỗi.

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

### Yêu cầu bổ sung — Thử nghiệm file hàng GB, đo thời gian, so sánh byte

**a) Tạo file lớn để thử:** thêm nút **"Tạo tệp thử nghiệm"** sinh file ngẫu nhiên có kích thước tuỳ chọn (ví dụ 1024 MB = 1 GB), vì không phải máy nào cũng có sẵn file hàng GB.

**b) Tính thời gian:** dùng `Stopwatch` bao quanh đúng phần mã hoá và đúng phần giải mã. Quy đổi ra **MB/s** để so sánh công bằng giữa các kích thước.

**c) So sánh theo byte:** đọc song song hai file theo từng khối 1 MiB, so khối bằng `CommonPrefixLength`. Kết quả:

- Nếu khác độ dài → khác ngay.

- Nếu có byte lệch → báo **vị trí byte lệch đầu tiên**.

- Nếu giống hết → xác nhận "giống hệt từng byte".

**d) Nút "Chạy trọn gói":** tự động thực hiện Mã hoá → Giải mã → So sánh, rồi ghi một dòng **bảng Markdown** vào nhật ký để dán thẳng vào báo cáo.

## 1.2 Các bước thực hiện

**Bước 1.** Tạo thư mục `Bai1_AES`, tạo hai file `AesStudio.csproj` và `Program.cs` với nội dung ở mục 1.3.

**Bước 2.** Mở terminal tại thư mục đó và chạy `dotnet run -c Release`.

**Bước 3.** Ở khung **① KHOÁ**: chọn 256, bấm **Sinh khoá**. Bấm **Lưu ra file** để lưu `aes.key`. Bấm **Nạp từ file** để kiểm tra nạp lại đúng khoá (vân tay SHA-256 phải trùng).

**Bước 4.** Ở khung **② VĂN BẢN**: nhập văn bản, bấm **Mã hoá** để thấy chuỗi Base64. Bấm **⇅ Đưa kết quả lên ô nhập** rồi **Giải mã** để thấy văn bản gốc trở lại.

**Bước 5.** Ở khung **③ TỆP**: nhập 1024 MB, bấm **Tạo tệp thử nghiệm**, chọn nơi lưu.

**Bước 6.** Bấm **▶ CHẠY TRỌN GÓI**. Chờ thanh tiến độ chạy xong, đọc thời gian và kết quả so sánh byte.

**Bước 7.** Lặp lại với 256 MB, 1024 MB, 2048 MB (hoặc lớn hơn nếu ổ đĩa cho phép). Ghi số liệu vào bảng ở mục 1.5.

**Bước 8.** Chụp ảnh màn hình các bước theo gợi ý ở mục 1.4.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/ffc506c5-6b82-4396-ac39-e1a046d583d5" />

