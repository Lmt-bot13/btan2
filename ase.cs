using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace AesStudio;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

// ==== CORE BEGIN ==========================================================
/// <summary>Lõi mật mã: AES-CBC + PKCS7. Định dạng tệp .enc = [16 byte IV][ciphertext].</summary>
internal static class AesCore
{
    private const int BufSize = 1 << 20; // 1 MiB: RAM cố định dù tệp bao nhiêu GB

    public static byte[] NewKey(int bits)
    {
        var key = new byte[bits / 8];
        RandomNumberGenerator.Fill(key);          // CSPRNG, không dùng Random
        return key;
    }

    public static string EncryptText(string text, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();                         // IV mới cho MỖI lần mã hoá
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), aes.IV, PaddingMode.PKCS7);
        byte[] all = new byte[16 + cipher.Length];
        Buffer.BlockCopy(aes.IV, 0, all, 0, 16);
        Buffer.BlockCopy(cipher, 0, all, 16, cipher.Length);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string base64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(base64.Trim());
        if (all.Length < 32) throw new CryptographicException("Chuỗi mã hoá quá ngắn hoặc sai định dạng.");
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] plain = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16), PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plain);
    }

    public static void EncryptFile(string src, string dst, byte[] key, IProgress<int> progress)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        fout.Write(aes.IV, 0, 16);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Pump(fin, cs, fin.Length, progress);
    }

    public static void DecryptFile(string src, string dst, byte[] key, IProgress<int> progress)
    {
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        var iv = new byte[16];
        fin.ReadExactly(iv);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        Pump(cs, fout, fin.Length - 16, progress);
    }

    /// <summary>So sánh từng byte hai tệp, trả về (giống?, độ dài, vị trí lệch đầu tiên).</summary>
    public static (bool Same, long Length, long FirstDiff) Compare(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return (false, fa.Length, Math.Min(fa.Length, fb.Length));

        var ba = new byte[BufSize];
        var bb = new byte[BufSize];
        long pos = 0;
        while (pos < fa.Length)
        {
            int n = (int)Math.Min(BufSize, fa.Length - pos);
            fa.ReadExactly(ba, 0, n);
            fb.ReadExactly(bb, 0, n);
            int diff = MemoryExtensions.CommonPrefixLength<byte>(ba.AsSpan(0, n), bb.AsSpan(0, n));
            if (diff < n) return (false, fa.Length, pos + diff);
            pos += n;
        }
        return (true, fa.Length, -1);
    }

    /// <summary>Tạo tệp ngẫu nhiên kích thước tuỳ ý (hàng GB) để thử nghiệm.</summary>
    public static void MakeTestFile(string path, long bytes, IProgress<int> progress)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        var buf = new byte[BufSize];
        long done = 0;
        int last = -1;
        while (done < bytes)
        {
            Random.Shared.NextBytes(buf);
            int n = (int)Math.Min(BufSize, bytes - done);
            fs.Write(buf, 0, n);
            done += n;
            int pc = (int)(done * 100 / bytes);
            if (pc != last) { progress.Report(pc); last = pc; }
        }
    }

    private static void Pump(Stream from, Stream to, long total, IProgress<int> progress)
    {
        var buf = new byte[BufSize];
        long done = 0;
        int n, last = -1;
        while ((n = from.Read(buf, 0, buf.Length)) > 0)
        {
            to.Write(buf, 0, n);
            done += n;
            int pc = total > 0 ? (int)Math.Min(100, done * 100 / total) : 100;
            if (pc != last) { progress.Report(pc); last = pc; }
        }
    }
}
// ==== CORE END ============================================================

internal sealed class MainForm : Form
{
    private static readonly Color Bg = Color.FromArgb(11, 13, 22);
    private static readonly Color CardBg = Color.FromArgb(24, 28, 44);
    private static readonly Color InputBg = Color.FromArgb(15, 18, 30);
    private static readonly Color Accent = Color.FromArgb(0, 224, 198);
    private static readonly Color Fg = Color.FromArgb(232, 236, 248);
    private static readonly Color Muted = Color.FromArgb(132, 142, 172);
    private static readonly Color Good = Color.FromArgb(80, 227, 140);

    private byte[]? _key;
    private readonly TextBox _txtKey, _txtIn, _txtOut, _txtSrc, _txtLog;
    private readonly ComboBox _cmbBits;
    private readonly NumericUpDown _numMb;
    private readonly CheckBox _chkClean;
    private readonly ProgressBar _bar;
    private readonly Label _lblKey, _lblStat;
    private readonly Progress<int> _prog;
    private bool _busy;
    private double _encSec = -1, _decSec = -1;
    private long _size = -1;
    private string _cmp = "—";

    public MainForm()
    {
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "AES Studio – Bài 1: Mã hoá đối xứng";
        ClientSize = new Size(1180, 760);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Bg;
        ForeColor = Fg;
        Font = new Font("Segoe UI", 9.5f);

        Controls.Add(new Label { Text = "AES Studio", Font = new Font("Segoe UI Semibold", 22f), ForeColor = Fg, Left = 24, Top = 12, AutoSize = true });
        Controls.Add(new Label { Text = "AES-CBC · khoá 128/192/256 bit · xử lý tệp dạng luồng (streaming) · đo thời gian · so sánh từng byte", ForeColor = Muted, Left = 28, Top = 56, AutoSize = true });

        // ① KHOÁ ---------------------------------------------------------
        var cKey = Card("①  KHOÁ AES", 24, 88, 540, 160);
        _txtKey = Box(cKey, 16, 44, 508, 28, ro: true);
        _cmbBits = new ComboBox { Left = 16, Top = 88, Width = 80, DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = InputBg, ForeColor = Fg };
        _cmbBits.Items.AddRange(new object[] { "128", "192", "256" });
        _cmbBits.SelectedIndex = 2;
        cKey.Controls.Add(_cmbBits);
        Btn(cKey, "Sinh khoá", 106, 84, 120, 34, () => Safe(GenKey), true);
        Btn(cKey, "Lưu ra file", 234, 84, 140, 34, () => Safe(SaveKey));
        Btn(cKey, "Nạp từ file", 382, 84, 142, 34, () => Safe(LoadKey));
        _lblKey = Lbl(cKey, "Chưa có khoá – hãy sinh hoặc nạp khoá.", 16, 128, Muted);

        // ② VĂN BẢN ------------------------------------------------------
        var cText = Card("②  MÃ HOÁ VĂN BẢN", 24, 262, 540, 306);
        _txtIn = Box(cText, 16, 44, 508, 90, multi: true);
        _txtIn.Text = "Xin chào AES! Đây là văn bản thử nghiệm.";
        Btn(cText, "Mã hoá", 16, 142, 150, 34, () => Safe(EncText), true);
        Btn(cText, "Giải mã", 174, 142, 150, 34, () => Safe(DecText));
        Btn(cText, "⇅  Đưa kết quả lên ô nhập", 332, 142, 192, 34, () => { _txtIn.Text = _txtOut.Text; });
        Lbl(cText, "Kết quả (Base64 = IV ‖ bản mã, hoặc bản rõ khi giải mã)", 16, 184, Muted);
        _txtOut = Box(cText, 16, 206, 508, 84, multi: true, ro: true);

        // ③ TỆP ----------------------------------------------------------
        var cFile = Card("③  MÃ HOÁ TỆP · ĐO HIỆU NĂNG", 580, 88, 576, 480);
        Lbl(cFile, "Tệp nguồn", 16, 42, Muted);
        _txtSrc = Box(cFile, 16, 64, 440, 28);
        Btn(cFile, "Chọn…", 464, 60, 96, 32, () => Safe(PickSrc));
        Lbl(cFile, "Tạo tệp ngẫu nhiên để thử nghiệm (MB) – 1024 MB = 1 GB", 16, 104, Muted);
        _numMb = new NumericUpDown { Left = 16, Top = 128, Width = 120, Minimum = 1, Maximum = 200000, Value = 512, BackColor = InputBg, ForeColor = Fg };
        cFile.Controls.Add(_numMb);
        Btn(cFile, "Tạo tệp thử nghiệm", 148, 124, 210, 34, () => _ = Guard(MakeFileAsync));
        Btn(cFile, "Mã hoá tệp", 16, 176, 170, 34, () => _ = Guard(EncFileAsync), true);
        Btn(cFile, "Giải mã tệp", 194, 176, 170, 34, () => _ = Guard(DecFileAsync));
        Btn(cFile, "So sánh byte", 372, 176, 188, 34, () => _ = Guard(CompareAsync));
        Btn(cFile, "▶  CHẠY TRỌN GÓI: Mã hoá → Giải mã → So sánh", 16, 222, 544, 42, () => _ = Guard(FullTestAsync), true);
        _chkClean = new CheckBox { Text = "Tự xoá tệp .enc / .dec sau khi kiểm thử (tiết kiệm ổ đĩa)", Left = 16, Top = 272, AutoSize = true, ForeColor = Muted };
        cFile.Controls.Add(_chkClean);
        _bar = new ProgressBar { Left = 16, Top = 304, Width = 544, Height = 16, Style = ProgressBarStyle.Continuous };
        cFile.Controls.Add(_bar);
        _lblStat = new Label { Left = 16, Top = 332, Width = 544, Height = 136, Font = new Font("Consolas", 10.5f), ForeColor = Fg };
        cFile.Controls.Add(_lblStat);
        _prog = new Progress<int>(v => _bar.Value = Math.Clamp(v, 0, 100));
        UpdateStats();

        // NHẬT KÝ --------------------------------------------------------
        var cLog = Card("NHẬT KÝ (sao chép dòng bảng Markdown để dán vào báo cáo)", 24, 584, 1132, 160);
        _txtLog = Box(cLog, 16, 40, 1100, 108, multi: true, ro: true);
        Log("Sẵn sàng. Bước 1: sinh hoặc nạp khoá.");
    }

    // ---------- khoá ----------
    private void GenKey()
    {
        _key = AesCore.NewKey(int.Parse(_cmbBits.Text));
        ShowKey();
        Log($"Đã sinh khoá AES-{_key.Length * 8} bit mới.");
    }

    private void ShowKey()
    {
        _txtKey.Text = Convert.ToBase64String(_key!);
        string fp = Convert.ToHexString(SHA256.HashData(_key!))[..16];
        _lblKey.Text = $"Khoá {_key!.Length * 8} bit ({_key.Length} byte) · vân tay SHA-256: {fp}…";
        _lblKey.ForeColor = Good;
    }

    private void SaveKey()
    {
        RequireKey();
        using var dlg = new SaveFileDialog { Filter = "Khoá AES (*.key)|*.key", FileName = "aes.key" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, Convert.ToBase64String(_key!));
        Log("Đã lưu khoá → " + dlg.FileName);
    }

    private void LoadKey()
    {
        using var dlg = new OpenFileDialog { Filter = "Khoá AES (*.key)|*.key|Tất cả|*.*" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        byte[] k = Convert.FromBase64String(File.ReadAllText(dlg.FileName).Trim());
        if (k.Length is not (16 or 24 or 32)) throw new InvalidOperationException($"Khoá không hợp lệ: {k.Length} byte (cần 16/24/32).");
        _key = k;
        ShowKey();
        Log("Đã nạp khoá từ " + dlg.FileName);
    }

    // ---------- văn bản ----------
    private void EncText()
    {
        RequireKey();
        if (_txtIn.Text.Length == 0) throw new InvalidOperationException("Hãy nhập văn bản cần mã hoá.");
        var sw = Stopwatch.StartNew();
        _txtOut.Text = AesCore.EncryptText(_txtIn.Text, _key!);
        sw.Stop();
        Log($"Mã hoá văn bản ({Encoding.UTF8.GetByteCount(_txtIn.Text)} byte) trong {sw.Elapsed.TotalMilliseconds:F3} ms.");
    }

    private void DecText()
    {
        RequireKey();
        var sw = Stopwatch.StartNew();
        _txtOut.Text = AesCore.DecryptText(_txtIn.Text, _key!);
        sw.Stop();
        Log($"Giải mã văn bản trong {sw.Elapsed.TotalMilliseconds:F3} ms.");
    }

    // ---------- tệp ----------
    private void PickSrc()
    {
        using var dlg = new OpenFileDialog();
        if (dlg.ShowDialog() == DialogResult.OK) _txtSrc.Text = dlg.FileName;
    }

    private (string orig, string enc, string dec) Paths()
    {
        string s = _txtSrc.Text.Trim();
        string orig = s.EndsWith(".enc", StringComparison.OrdinalIgnoreCase) ? s[..^4] : s;
        return (orig, orig + ".enc", orig + ".dec");
    }

    private static void RequireFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Không tìm thấy tệp: " + path);
    }

    private async Task MakeFileAsync()
    {
        using var dlg = new SaveFileDialog { Filter = "Tệp nhị phân (*.bin)|*.bin", FileName = $"test_{_numMb.Value}MB.bin" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        long bytes = (long)_numMb.Value * 1048576L;
        string path = dlg.FileName;
        double s = await TimedAsync(() => AesCore.MakeTestFile(path, bytes, _prog));
        _txtSrc.Text = path;
        Log($"Đã tạo tệp {bytes / 1048576:N0} MB trong {s:F1} s → {path}");
    }

    private async Task EncFileAsync()
    {
        RequireKey();
        var (orig, enc, _) = Paths();
        RequireFile(orig);
        _size = new FileInfo(orig).Length;
        _encSec = await TimedAsync(() => AesCore.EncryptFile(orig, enc, _key!, _prog));
        UpdateStats();
        Log($"Mã hoá {_size / 1048576.0:N2} MB trong {_encSec:F2} s → {enc}");
    }

    private async Task DecFileAsync()
    {
        RequireKey();
        var (_, enc, dec) = Paths();
        RequireFile(enc);
        _decSec = await TimedAsync(() => AesCore.DecryptFile(enc, dec, _key!, _prog));
        UpdateStats();
        Log($"Giải mã trong {_decSec:F2} s → {dec}");
    }

    private async Task CompareAsync()
    {
        var (orig, _, dec) = Paths();
        RequireFile(orig);
        RequireFile(dec);
        var sw = Stopwatch.StartNew();
        var r = await Task.Run(() => AesCore.Compare(orig, dec));
        sw.Stop();
        SetCmp(r);
        UpdateStats();
        Log($"So sánh byte: {_cmp} (mất {sw.Elapsed.TotalSeconds:F2} s)");
    }

    private async Task FullTestAsync()
    {
        RequireKey();
        var (orig, enc, dec) = Paths();
        RequireFile(orig);
        _size = new FileInfo(orig).Length;
        Log($"▶ Kiểm thử trọn gói: {orig} ({_size / 1048576.0:N0} MB, khoá {_key!.Length * 8} bit)");

        _encSec = await TimedAsync(() => AesCore.EncryptFile(orig, enc, _key!, _prog));
        _decSec = await TimedAsync(() => AesCore.DecryptFile(enc, dec, _key!, _prog));
        var r = await Task.Run(() => AesCore.Compare(orig, dec));
        SetCmp(r);
        UpdateStats();

        double mb = _size / 1048576.0;
        Log($"| {mb:N0} | {_encSec:F2} | {_decSec:F2} | {mb / _encSec:F1} | {mb / _decSec:F1} | {(r.Same ? "Khớp 100%" : "KHÁC")} |");

        if (_chkClean.Checked)
        {
            File.Delete(enc);
            File.Delete(dec);
            Log("Đã xoá tệp .enc / .dec tạm.");
        }
    }

    private void SetCmp((bool Same, long Length, long FirstDiff) r) =>
        _cmp = r.Same ? $"✔ GIỐNG HỆT từng byte ({r.Length:N0} byte)" : $"✘ KHÁC nhau, byte lệch đầu tiên: #{r.FirstDiff:N0}";

    private void UpdateStats()
    {
        string T(double s) => s < 0 ? "—" : $"{s:F2} s  →  {_size / 1048576.0 / Math.Max(s, 1e-9):F1} MB/s";
        _lblStat.Text =
            $"Kích thước tệp   : {(_size < 0 ? "—" : (_size / 1048576.0).ToString("N2") + " MB")}\r\n\r\n" +
            $"Thời gian mã hoá : {T(_encSec)}\r\n" +
            $"Thời gian giải mã: {T(_decSec)}\r\n\r\n" +
            $"So sánh byte     : {_cmp}";
        _lblStat.ForeColor = _cmp.StartsWith("✘") ? Color.FromArgb(255, 107, 107) : Fg;
    }

    private static async Task<double> TimedAsync(Action work)
    {
        var sw = Stopwatch.StartNew();
        await Task.Run(work);
        return sw.Elapsed.TotalSeconds;
    }

    // ---------- tiện ích ----------
    private void RequireKey()
    {
        if (_key == null) throw new InvalidOperationException("Chưa có khoá – hãy sinh hoặc nạp khoá trước.");
    }

    private void Safe(Action a)
    {
        try { a(); } catch (Exception ex) { Fail(ex); }
    }

    private async Task Guard(Func<Task> work)
    {
        if (_busy) { Log("⏳ Đang xử lý, vui lòng chờ…"); return; }
        _busy = true;
        UseWaitCursor = true;
        _bar.Value = 0;
        try { await work(); }
        catch (Exception ex) { Fail(ex); }
        finally { _busy = false; UseWaitCursor = false; }
    }

    private void Fail(Exception ex)
    {
        Log("✖ " + ex.Message);
        MessageBox.Show(ex.Message, "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private void Log(string s) => _txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {s}{Environment.NewLine}");

    // ---------- dựng giao diện ----------
    private Panel Card(string title, int x, int y, int w, int h)
    {
        var p = new Panel { Left = x, Top = y, Width = w, Height = h, BackColor = CardBg };
        p.Controls.Add(new Label { Text = title, ForeColor = Accent, Font = new Font("Segoe UI Semibold", 10.5f), Left = 16, Top = 12, AutoSize = true });
        Controls.Add(p);
        return p;
    }

    private static Label Lbl(Control parent, string text, int x, int y, Color color)
    {
        var l = new Label { Text = text, Left = x, Top = y, AutoSize = true, ForeColor = color };
        parent.Controls.Add(l);
        return l;
    }

    private static TextBox Box(Control parent, int x, int y, int w, int h, bool multi = false, bool ro = false)
    {
        var t = new TextBox
        {
            Left = x, Top = y, Width = w, Height = h, Multiline = multi, ReadOnly = ro,
            BorderStyle = BorderStyle.FixedSingle, BackColor = InputBg, ForeColor = Fg, Font = new Font("Consolas", 10f)
        };
        if (multi) t.ScrollBars = ScrollBars.Vertical;
        parent.Controls.Add(t);
        return t;
    }

    private static Button Btn(Control parent, string text, int x, int y, int w, int h, Action onClick, bool primary = false)
    {
        var b = new Button
        {
            Text = text, Left = x, Top = y, Width = w, Height = h, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
            BackColor = primary ? Accent : Color.FromArgb(40, 46, 70),
            ForeColor = primary ? Color.FromArgb(6, 20, 24) : Fg,
            Font = new Font("Segoe UI Semibold", 9.5f)
        };
        b.FlatAppearance.BorderSize = 0;
        b.Click += (_, _) => onClick();
        parent.Controls.Add(b);
        return b;
    }
}
