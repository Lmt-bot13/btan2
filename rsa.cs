using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaStudio;

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

/// <summary>Giải phẫu PEM: Base64 → DER → cây ASN.1 (Tag | Length | Value) + tham số RSA.</summary>
internal static class Asn1
{
    private sealed record Node(int Pos, byte Tag, int Hdr, int ValStart, int Len);

    public static string Describe(string pem)
    {
        PemFields f = PemEncoding.Find(pem.AsSpan());
        string label = pem[f.Label];
        string b64 = pem[f.Base64Data];
        byte[] der = Convert.FromBase64String(b64);
        bool priv = label.Contains("PRIVATE", StringComparison.OrdinalIgnoreCase);

        var sb = new StringBuilder();
        sb.AppendLine($"Dòng mở đầu : -----BEGIN {label}-----");
        sb.AppendLine($"Base64      : {b64.Count(c => !char.IsWhiteSpace(c))} ký tự  (6 bit/ký tự → 3 byte = 4 ký tự)");
        sb.AppendLine($"DER nhị phân: {der.Length} byte");
        sb.AppendLine($"16 byte đầu : {Hex(der, 0, Math.Min(16, der.Length))}");
        sb.AppendLine();
        sb.AppendLine("QUY TẮC DER: mỗi phần tử = [Tag 1 byte][Length 1–5 byte][Value]");
        sb.AppendLine("  Length < 128  → 1 byte.   Length ≥ 128 → 0x8N rồi N byte độ dài (vd 82 01 22 = 0x0122 = 290)");
        sb.AppendLine();
        sb.AppendLine("CÂY ASN.1  (vị trí | byte Tag+Length | loại | độ dài)");
        sb.AppendLine(new string('─', 74));
        try { Dump(der, 0, der.Length, 0, sb); }
        catch (FormatException) { sb.AppendLine("(không phân tích được cấu trúc DER)"); }

        sb.AppendLine(new string('─', 74));
        sb.AppendLine("THAM SỐ RSA");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        RSAParameters p = rsa.ExportParameters(priv);
        BigInteger e = new(p.Exponent!, true, true);
        sb.AppendLine($"n  ({BitLen(p.Modulus!)} bit) = p·q — modulus:");
        sb.AppendLine("    " + Wrap(Convert.ToHexString(p.Modulus!), 64));
        sb.AppendLine($"e  ({e.GetBitLength()} bit) = {e}  (0x{Convert.ToHexString(p.Exponent!)})");
        if (priv)
        {
            Row(sb, "d ", "privateExponent, e·d ≡ 1 (mod λ(n))", p.D);
            Row(sb, "p ", "số nguyên tố thứ nhất", p.P);
            Row(sb, "q ", "số nguyên tố thứ hai", p.Q);
            Row(sb, "dP", "d mod (p−1)", p.DP);
            Row(sb, "dQ", "d mod (q−1)", p.DQ);
            Row(sb, "qI", "q⁻¹ mod p (dùng cho CRT)", p.InverseQ);
            var n = new BigInteger(p.Modulus!, true, true);
            var pp = new BigInteger(p.P!, true, true);
            var qq = new BigInteger(p.Q!, true, true);
            sb.AppendLine();
            sb.AppendLine($"Kiểm tra: p·q == n ? {(pp * qq == n ? "ĐÚNG ✔" : "SAI ✘")}");
        }
        return sb.ToString();
    }

    private static void Row(StringBuilder sb, string name, string meaning, byte[]? v)
    {
        if (v == null) return;
        sb.AppendLine($"{name} ({BitLen(v)} bit) — {meaning}:");
        sb.AppendLine("    " + Wrap(Convert.ToHexString(v), 64));
    }

    private static int BitLen(byte[] v) => (int)new BigInteger(v, true, true).GetBitLength();

    private static string Wrap(string s, int w) =>
        string.Join(Environment.NewLine + "    ",
            Enumerable.Range(0, (s.Length + w - 1) / w).Select(i => s.Substring(i * w, Math.Min(w, s.Length - i * w))));

    private static string Hex(byte[] b, int start, int count) =>
        string.Join(" ", b.Skip(start).Take(count).Select(x => x.ToString("X2")));

    private static List<Node> Parse(byte[] b, int s, int e)
    {
        var list = new List<Node>();
        int i = s;
        while (i < e)
        {
            int pos = i;
            if (i + 2 > e) throw new FormatException();
            byte tag = b[i++];
            int len = b[i++];
            if ((len & 0x80) != 0)
            {
                int nb = len & 0x7F;
                if (nb == 0 || nb > 4 || i + nb > e) throw new FormatException();
                len = 0;
                for (int k = 0; k < nb; k++) len = (len << 8) | b[i++];
            }
            if (len < 0 || i + len > e) throw new FormatException();
            list.Add(new Node(pos, tag, i - pos, i, len));
            i += len;
        }
        return list;
    }

    private static string Name(byte t) => t switch
    {
        0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x03 => "BIT STRING", 0x04 => "OCTET STRING",
        0x05 => "NULL", 0x06 => "OBJECT IDENTIFIER", _ => "TAG?"
    };

    private static string Meaning(byte t) => t switch
    {
        0x30 => "nhóm các trường con",
        0x02 => "số nguyên lớn (big-endian)",
        0x03 => "chuỗi bit – bọc public key; byte đầu = số bit thừa",
        0x04 => "chuỗi byte – bọc RSAPrivateKey",
        0x05 => "rỗng (tham số thuật toán)",
        0x06 => "định danh thuật toán",
        _ => ""
    };

    private static void Dump(byte[] b, int s, int e, int depth, StringBuilder sb)
    {
        List<Node> nodes = Parse(b, s, e);
        string[]? labels = null;
        if (nodes.Count > 0 && nodes.All(n => n.Tag == 0x02))
        {
            if (nodes.Count == 9)
                labels = new[] { "version = 0", "n (modulus)", "e (publicExponent)", "d (privateExponent)", "p", "q", "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q^-1 mod p" };
            else if (nodes.Count == 2)
                labels = new[] { "n (modulus)", "e (publicExponent)" };
        }

        string pad = new(' ', depth * 3);
        for (int k = 0; k < nodes.Count; k++)
        {
            Node n = nodes[k];
            string hdr = Hex(b, n.Pos, n.Hdr);
            sb.Append($"{pad}@{n.Pos:D4} | {hdr,-12} | {Name(n.Tag),-17} | len={n.Len}");
            if (labels != null) sb.Append($"  ◄ {labels[k]}");
            sb.AppendLine();
            if (n.Tag != 0x30 && Meaning(n.Tag).Length > 0) sb.AppendLine($"{pad}       ↳ {Meaning(n.Tag)}");

            switch (n.Tag)
            {
                case 0x30:
                    Dump(b, n.ValStart, n.ValStart + n.Len, depth + 1, sb);
                    break;
                case 0x02:
                    sb.AppendLine($"{pad}       ↳ {IntInfo(b, n)}");
                    break;
                case 0x06:
                    sb.AppendLine($"{pad}       ↳ OID = {Oid(b, n.ValStart, n.Len)}");
                    break;
                case 0x03:
                case 0x04:
                    int vs = n.ValStart + (n.Tag == 0x03 ? 1 : 0);
                    var inner = new StringBuilder();
                    try
                    {
                        Dump(b, vs, n.ValStart + n.Len, depth + 1, inner);
                        sb.Append(inner);
                    }
                    catch (FormatException)
                    {
                        sb.AppendLine($"{pad}       ↳ bytes: {Hex(b, n.ValStart, Math.Min(n.Len, 24))} …");
                    }
                    break;
            }
        }
    }

    private static string IntInfo(byte[] b, Node n)
    {
        var bi = new BigInteger(b.AsSpan(n.ValStart, n.Len), true, true);
        string lead = n.Len > 1 && b[n.ValStart] == 0 ? " · byte 00 đứng đầu để số luôn dương" : "";
        if (n.Len <= 8) return $"giá trị = {bi} (0x{Convert.ToHexString(b, n.ValStart, n.Len)}){lead}";
        return $"{bi.GetBitLength()} bit · bắt đầu bằng {Convert.ToHexString(b, n.ValStart, 8)}…{lead}";
    }

    private static string Oid(byte[] b, int s, int len)
    {
        if (len == 0) return "";
        var parts = new List<string> { (b[s] / 40).ToString(), (b[s] % 40).ToString() };
        long v = 0;
        for (int i = s + 1; i < s + len; i++)
        {
            v = (v << 7) | (uint)(b[i] & 0x7F);
            if ((b[i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        string oid = string.Join(".", parts);
        return oid == "1.2.840.113549.1.1.1" ? oid + "  (rsaEncryption)" : oid;
    }
}

internal static class HashUtil
{
    public static int Hamming(byte[] a, byte[] b)
    {
        int c = 0;
        for (int i = 0; i < a.Length; i++) c += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return c;
    }
}

/// <summary>Ba cách ký: PKCS#1 v1.5 (xác định), RSA-PSS (ngẫu nhiên), Nonce + PKCS#1.</summary>
internal static class Signer
{
    public static byte[] SignPkcs1(RSA k, byte[] data) =>
        k.SignHash(SHA256.HashData(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public static byte[] SignPss(RSA k, byte[] data) =>
        k.SignHash(SHA256.HashData(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public static bool Verify(RSA k, byte[] data, byte[] sig, RSASignaturePadding pad) =>
        k.VerifyHash(SHA256.HashData(data), sig, HashAlgorithmName.SHA256, pad);

    /// <summary>Gói chữ ký = Base64(nonce) + "." + Base64(chữ ký của SHA256(nonce ‖ dữ liệu)).</summary>
    public static string SignNonce(RSA k, byte[] data)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        byte[] sig = k.SignHash(Digest(nonce, data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(nonce) + "." + Convert.ToBase64String(sig);
    }

    public static bool VerifyNonce(RSA k, byte[] data, string bundle)
    {
        string[] parts = bundle.Split('.');
        if (parts.Length != 2) return false;
        return k.VerifyHash(Digest(Convert.FromBase64String(parts[0]), data), Convert.FromBase64String(parts[1]),
                            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static byte[] Digest(byte[] nonce, byte[] data)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(nonce);
        h.AppendData(data);
        return h.GetHashAndReset();
    }
}

/// <summary>Đo tốc độ: khoá công khai (e nhỏ) so với khoá riêng (d to).</summary>
internal static class Bench
{
    private static double AvgMs(int n, Action a)
    {
        a(); a();                                   // khởi động (JIT, cache)
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < n; i++) a();
        sw.Stop();
        return sw.Elapsed.TotalMilliseconds / n;
    }

    private static string Bar(double v, double max) => new('█', Math.Max(1, (int)Math.Round(v / max * 36)));

    public static string Run(RSA rsa, int n)
    {
        RSAParameters p = rsa.ExportParameters(true);
        BigInteger N = new(p.Modulus!, true, true), E = new(p.Exponent!, true, true), D = new(p.D!, true, true);
        var sb = new StringBuilder();
        sb.AppendLine($"KHOÁ     : RSA-{rsa.KeySize}   n = {N.GetBitLength()} bit");
        sb.AppendLine($"           e = {E}  ({E.GetBitLength()} bit)   ← NHỎ");
        sb.AppendLine($"           d = {D.GetBitLength()} bit            ← TO ĐÙNG");
        sb.AppendLine($"Số lần lặp mỗi phép đo: {n}");
        sb.AppendLine();

        byte[] msg = RandomNumberGenerator.GetBytes(32);
        byte[] ct = rsa.Encrypt(msg, RSAEncryptionPadding.OaepSHA256);
        double enc = AvgMs(n, () => rsa.Encrypt(msg, RSAEncryptionPadding.OaepSHA256));
        double dec = AvgMs(n, () => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256));
        double max = Math.Max(enc, dec);
        sb.AppendLine("A) RSA-OAEP-SHA256 trên 32 byte (khoá AES-256) — .NET có dùng CRT cho khoá riêng");
        sb.AppendLine($"   Mã hoá  · PUBLIC  (e nhỏ) : {enc,9:F4} ms/lần  {1000 / enc,9:F0} lần/s  {Bar(enc, max)}");
        sb.AppendLine($"   Giải mã · PRIVATE (d to)  : {dec,9:F4} ms/lần  {1000 / dec,9:F0} lần/s  {Bar(dec, max)}");
        sb.AppendLine($"   → Giải mã chậm hơn mã hoá khoảng {dec / enc:F1} lần");
        sb.AppendLine();

        byte[] data = RandomNumberGenerator.GetBytes(256);
        byte[] sig = Signer.SignPkcs1(rsa, data);
        double sign = AvgMs(n, () => Signer.SignPkcs1(rsa, data));
        double ver = AvgMs(n, () => Signer.Verify(rsa, data, sig, RSASignaturePadding.Pkcs1));
        max = Math.Max(sign, ver);
        sb.AppendLine("B) Chữ ký số PKCS#1 v1.5 + SHA-256");
        sb.AppendLine($"   Xác minh · PUBLIC  (e nhỏ): {ver,9:F4} ms/lần  {1000 / ver,9:F0} lần/s  {Bar(ver, max)}");
        sb.AppendLine($"   Ký       · PRIVATE (d to) : {sign,9:F4} ms/lần  {1000 / sign,9:F0} lần/s  {Bar(sign, max)}");
        sb.AppendLine($"   → Ký chậm hơn xác minh khoảng {sign / ver:F1} lần");
        sb.AppendLine();

        var mb = new byte[p.Modulus!.Length - 1];
        RandomNumberGenerator.Fill(mb);
        BigInteger m = new BigInteger(mb, true, true) + 2;
        int nd = Math.Min(n, 50);
        double me = AvgMs(n, () => BigInteger.ModPow(m, E, N));
        double md = AvgMs(nd, () => BigInteger.ModPow(m, D, N));
        max = Math.Max(me, md);
        sb.AppendLine($"C) RSA 'thô' bằng BigInteger.ModPow (KHÔNG CRT) — thấy rõ ảnh hưởng của số mũ  (d đo {nd} lần)");
        sb.AppendLine($"   m^e mod n  (e {E.GetBitLength(),4} bit) : {me,9:F4} ms/lần  {Bar(me, max)}");
        sb.AppendLine($"   m^d mod n  (d {D.GetBitLength(),4} bit) : {md,9:F4} ms/lần  {Bar(md, max)}");
        sb.AppendLine($"   → Số mũ d chậm hơn e khoảng {md / me:F1} lần (≈ tỉ lệ số bit của số mũ)");
        return sb.ToString();
    }
}
// ==== CORE END ============================================================

/// <summary>Lưới 16×16 = 256 bit của giá trị băm; viền cam = bit khác lần trước.</summary>
internal sealed class BitGrid : Control
{
    private byte[]? _cur, _prev;

    public BitGrid()
    {
        DoubleBuffered = true;
        Size = new Size(322, 322);
    }

    public void SetHashes(byte[] cur, byte[]? prev)
    {
        _cur = cur;
        _prev = prev;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Color.FromArgb(18, 15, 32));
        if (_cur == null) return;
        const int cell = 20;
        using var on = new SolidBrush(Color.FromArgb(167, 139, 250));
        using var off = new SolidBrush(Color.FromArgb(40, 36, 66));
        using var pen = new Pen(Color.FromArgb(251, 146, 60), 2);
        for (int i = 0; i < 256; i++)
        {
            bool bit = ((_cur[i / 8] >> (7 - i % 8)) & 1) == 1;
            bool changed = _prev != null && (((_prev[i / 8] >> (7 - i % 8)) & 1) == 1) != bit;
            var r = new Rectangle(i % 16 * cell + 2, i / 16 * cell + 2, cell - 4, cell - 4);
            g.FillRectangle(bit ? on : off, r);
            if (changed) g.DrawRectangle(pen, r);
        }
    }
}

internal sealed class MainForm : Form
{
    private static readonly Color Bg = Color.FromArgb(14, 12, 24);
    private static readonly Color Side = Color.FromArgb(22, 19, 38);
    private static readonly Color InputBg = Color.FromArgb(22, 19, 40);
    private static readonly Color Accent = Color.FromArgb(167, 139, 250);
    private static readonly Color Fg = Color.FromArgb(236, 233, 250);
    private static readonly Color Muted = Color.FromArgb(138, 132, 170);
    private static readonly Color Good = Color.FromArgb(74, 222, 128);
    private static readonly Color Bad = Color.FromArgb(251, 113, 133);
    private static readonly Color Warn = Color.FromArgb(251, 146, 60);

    private RSA? _priv, _pub;
    private bool _busy;
    private readonly Panel[] _pages = new Panel[5];
    private readonly Button[] _nav = new Button[5];
    private readonly Label _lblState;

    // trang 1
    private ComboBox _cmbSize = null!;
    private TextBox _pubBox = null!, _privBox = null!, _asnBox = null!;
    // trang 2
    private TextBox _inBox = null!, _cipherBox = null!, _plainBox = null!, _pemPath = null!, _cipherPath = null!;
    private CheckBox _chkB64 = null!;
    private Label _lblLen = null!, _lblCmp = null!;
    // trang 3
    private NumericUpDown _numIter = null!;
    private TextBox _benchBox = null!;
    // trang 4
    private TextBox _hashIn = null!;
    private RichTextBox _rtbCur = null!;
    private Label _lblPrev = null!, _lblDiff = null!;
    private BitGrid _grid = null!;
    private byte[]? _curHash, _prevHash;
    private readonly List<double> _diffPct = new();
    // trang 5
    private TextBox _sigIn = null!, _sigOut = null!;

    public MainForm()
    {
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "RSA Lab – Bài 2: Mã hoá bất đối xứng · SHA-256 · Chữ ký số";
        ClientSize = new Size(1260, 800);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Bg;
        ForeColor = Fg;
        Font = new Font("Segoe UI", 9.5f);

        var side = new Panel { Left = 0, Top = 0, Width = 230, Height = 800, BackColor = Side };
        Controls.Add(side);
        side.Controls.Add(new Label { Text = "RSA Lab", Font = new Font("Segoe UI Semibold", 22f), ForeColor = Fg, Left = 18, Top = 20, AutoSize = true });
        side.Controls.Add(new Label { Text = "Bài 2 · Bất đối xứng", ForeColor = Muted, Left = 22, Top = 64, AutoSize = true });
        string[] names = { "①  Khoá & PEM", "②  Mã hoá · Giải mã", "③  Tốc độ: e vs d", "④  Băm SHA-256", "⑤  Chữ ký số" };
        for (int i = 0; i < names.Length; i++)
        {
            int idx = i;
            _nav[i] = Btn(side, names[i], 10, 110 + i * 54, 210, 44, () => ShowPage(idx));
            _nav[i].TextAlign = ContentAlignment.MiddleLeft;
        }
        _lblState = new Label { Left = 18, Top = 620, Width = 200, Height = 150, ForeColor = Muted, Font = new Font("Consolas", 9.5f) };
        side.Controls.Add(_lblState);

        var host = new Panel { Left = 230, Top = 0, Width = 1030, Height = 800, BackColor = Bg };
        Controls.Add(host);
        _pages[0] = Build1();
        _pages[1] = Build2();
        _pages[2] = Build3();
        _pages[3] = Build4();
        _pages[4] = Build5();
        foreach (var pg in _pages) { pg.Dock = DockStyle.Fill; host.Controls.Add(pg); }

        ShowPage(0);
        UpdateState();
    }

    private void ShowPage(int idx)
    {
        for (int i = 0; i < _pages.Length; i++)
        {
            _pages[i].Visible = i == idx;
            _nav[i].BackColor = i == idx ? Accent : Color.FromArgb(34, 30, 58);
            _nav[i].ForeColor = i == idx ? Color.FromArgb(20, 12, 40) : Fg;
        }
    }

    private void UpdateState()
    {
        static string Line(string n, RSA? k) => k == null ? $"{n}: ✘ chưa có" : $"{n}: ✔ {k.KeySize} bit";
        _lblState.Text = "TRẠNG THÁI KHOÁ\r\n\r\n" + Line("Public ", _pub) + "\r\n" + Line("Private", _priv);
        if (_lblLen != null) UpdateLen();
    }

    private RSA RequirePub() => _pub ?? _priv ?? throw new InvalidOperationException("Chưa có public key – hãy sinh khoá hoặc nhập .pem ở trang ①.");
    private RSA RequirePriv() => _priv ?? throw new InvalidOperationException("Chưa có private key – hãy sinh khoá hoặc nhập .pem ở trang ①.");

    // ======================================================================
    // TRANG 1 — KHOÁ & PEM
    // ======================================================================
    private Panel Build1()
    {
        var p = new Panel { BackColor = Bg };
        Header(p, "①  Khoá & định dạng PEM", "Sinh cặp khoá · xuất / nhập .pem · giải phẫu từng byte DER · đọc n, e, d, p, q …");
        Lbl(p, "Độ dài khoá (bit)", 28, 96, Muted);
        _cmbSize = new ComboBox { Left = 28, Top = 120, Width = 110, DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = InputBg, ForeColor = Fg };
        _cmbSize.Items.AddRange(new object[] { "1024", "2048", "3072", "4096" });
        _cmbSize.SelectedIndex = 1;
        p.Controls.Add(_cmbSize);
        Btn(p, "⚙  Sinh cặp khoá", 150, 116, 190, 36, () => { _ = Guard(GenKeysAsync); }, true);

        Lbl(p, "PUBLIC KEY  (SubjectPublicKeyInfo · -----BEGIN PUBLIC KEY-----)", 28, 170, Accent);
        _pubBox = Box(p, 28, 194, 470, 150, multi: true);
        PemButtons(p, 352, _pubBox, false);

        Lbl(p, "PRIVATE KEY  (PKCS#8 · -----BEGIN PRIVATE KEY-----)", 28, 404, Accent);
        _privBox = Box(p, 28, 428, 470, 250, multi: true);
        PemButtons(p, 686, _privBox, true);

        Lbl(p, "PHÂN TÍCH ASN.1 DER · Ý NGHĨA TỪNG BYTE", 520, 170, Accent);
        _asnBox = Box(p, 520, 194, 484, 526, multi: true, ro: true, size: 9f);
        _asnBox.WordWrap = false;
        _asnBox.ScrollBars = ScrollBars.Both;
        _asnBox.Text = "Bấm “Sinh cặp khoá” hoặc “Nhập”, rồi “Phân tích”.\r\nVùng này sẽ hiển thị cây ASN.1, giải thích Tag-Length-Value và các tham số n, e, d, p, q …";
        return p;
    }

    private void PemButtons(Panel p, int y, TextBox box, bool priv)
    {
        Btn(p, "📂  Nhập", 28, y, 100, 34, () => Safe(() => ImportPem(box, priv)));
        Btn(p, "💾  Lưu .pem", 136, y, 120, 34, () => Safe(() => SavePem(box, priv)));
        Btn(p, "🔍  Phân tích", 264, y, 140, 34, () => Safe(() => Analyze(box, priv)), true);
    }

    private async Task GenKeysAsync()
    {
        int bits = int.Parse(_cmbSize.Text);
        var sw = Stopwatch.StartNew();
        var (privPem, pubPem) = await Task.Run(() =>
        {
            using var r = RSA.Create(bits);
            return (r.ExportPkcs8PrivateKeyPem(), r.ExportSubjectPublicKeyInfoPem());
        });
        sw.Stop();
        _privBox.Text = Crlf(privPem.Trim());
        _pubBox.Text = Crlf(pubPem.Trim());
        Analyze(_privBox, true);
        Analyze(_pubBox, false);
        _asnBox.Text = $"Đã sinh khoá RSA-{bits} trong {sw.ElapsedMilliseconds} ms.\r\n\r\n" + _asnBox.Text;
    }

    private void ImportPem(TextBox box, bool priv)
    {
        using var dlg = new OpenFileDialog { Filter = "PEM (*.pem;*.key;*.txt)|*.pem;*.key;*.txt|Tất cả|*.*" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        box.Text = Crlf(File.ReadAllText(dlg.FileName).Trim());
        Analyze(box, priv);
    }

    private void SavePem(TextBox box, bool priv)
    {
        Analyze(box, priv); // kiểm tra PEM hợp lệ trước khi lưu
        using var dlg = new SaveFileDialog { Filter = "PEM (*.pem)|*.pem", FileName = priv ? "private.pem" : "public.pem" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, box.Text.Trim().Replace("\r\n", "\n") + "\n");
        _asnBox.Text = "Đã lưu → " + dlg.FileName + "\r\n\r\n" + _asnBox.Text;
    }

    private void Analyze(TextBox box, bool priv)
    {
        string pem = box.Text.Trim().Replace("\r\n", "\n");
        if (pem.Length == 0) throw new InvalidOperationException("Khung PEM đang trống.");
        bool isPrivPem = pem.Contains("PRIVATE", StringComparison.Ordinal);
        if (isPrivPem != priv)
            throw new InvalidOperationException(priv ? "Nội dung này là public key – hãy dùng khung PUBLIC." : "Nội dung này là private key – hãy dùng khung PRIVATE.");
        var k = RSA.Create();
        k.ImportFromPem(pem);
        if (priv) { _priv?.Dispose(); _priv = k; } else { _pub?.Dispose(); _pub = k; }
        _asnBox.Text = Asn1.Describe(pem);
        UpdateState();
    }

    // ======================================================================
    // TRANG 2 — MÃ HOÁ / GIẢI MÃ
    // ======================================================================
    private Panel Build2()
    {
        var p = new Panel { BackColor = Bg };
        Header(p, "②  Mã hoá · Giải mã RSA-OAEP", "Mã hoá bằng public key · giải mã bằng private key · tối đa 190 byte (RSA-2048 + OAEP-SHA256)");

        Lbl(p, "DỮ LIỆU CẦN MÃ HOÁ", 28, 96, Accent);
        _inBox = Box(p, 28, 120, 970, 80, multi: true);
        _inBox.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _chkB64 = new CheckBox { Text = "Dữ liệu nhập là Base64 (mảng byte)", Left = 28, Top = 212, AutoSize = true, ForeColor = Fg, Checked = true };
        p.Controls.Add(_chkB64);
        _lblLen = Lbl(p, "", 330, 214, Muted);
        Btn(p, "🎲  Sinh khoá AES-256 ngẫu nhiên (32 byte)", 620, 206, 378, 34, () =>
        {
            _chkB64.Checked = true;
            _inBox.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        });
        _inBox.TextChanged += (_, _) => UpdateLen();
        _chkB64.CheckedChanged += (_, _) => UpdateLen();

        Btn(p, "🔒  MÃ HOÁ bằng Public Key  →  lưu file Base64", 28, 252, 470, 42, () => Safe(Encrypt), true);
        Lbl(p, "Kết quả mã hoá (Base64)", 28, 304, Muted);
        _cipherBox = Box(p, 28, 328, 970, 84, multi: true, ro: true);

        Lbl(p, "GIẢI MÃ", 28, 430, Accent);
        Lbl(p, "File private.pem (để trống = dùng private key đang nạp)", 28, 456, Muted);
        _pemPath = Box(p, 28, 478, 820, 28);
        Btn(p, "Chọn…", 860, 474, 138, 32, () => Safe(() => Pick(_pemPath, "PEM|*.pem;*.key;*.txt|Tất cả|*.*")));
        Lbl(p, "File dữ liệu đã mã hoá (Base64)", 28, 516, Muted);
        _cipherPath = Box(p, 28, 538, 820, 28);
        Btn(p, "Chọn…", 860, 534, 138, 32, () => Safe(() => Pick(_cipherPath, "Văn bản|*.txt;*.b64|Tất cả|*.*")));
        Btn(p, "🔓  GIẢI MÃ & so sánh với dữ liệu nguồn", 28, 580, 470, 42, () => Safe(Decrypt), true);
        _lblCmp = Lbl(p, "", 520, 590, Muted);
        Lbl(p, "Dữ liệu sau giải mã", 28, 634, Muted);
        _plainBox = Box(p, 28, 656, 970, 100, multi: true, ro: true);
        return p;
    }

    private byte[] GetInput() =>
        _chkB64.Checked ? Convert.FromBase64String(_inBox.Text.Trim()) : Encoding.UTF8.GetBytes(_inBox.Text);

    private void UpdateLen()
    {
        int max = ((_pub ?? _priv)?.KeySize ?? 2048) / 8 - 66; // k − 2·hLen − 2
        try
        {
            int n = GetInput().Length;
            _lblLen.Text = $"{n} byte / tối đa {max} byte";
            _lblLen.ForeColor = n > 0 && n <= max ? Good : Bad;
        }
        catch (FormatException)
        {
            _lblLen.Text = "Base64 không hợp lệ";
            _lblLen.ForeColor = Bad;
        }
    }

    private void Encrypt()
    {
        RSA k = RequirePub();
        byte[] data = GetInput();
        int max = k.KeySize / 8 - 66;
        if (data.Length == 0 || data.Length > max) throw new InvalidOperationException($"Dữ liệu phải từ 1 đến {max} byte (hiện {data.Length}).");
        string b64 = Convert.ToBase64String(k.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
        _cipherBox.Text = b64;
        using var dlg = new SaveFileDialog { Filter = "Văn bản (*.txt)|*.txt", FileName = "cipher_base64.txt" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, b64);
        _cipherPath.Text = dlg.FileName;
    }

    private void Decrypt()
    {
        using RSA? tmp = string.IsNullOrWhiteSpace(_pemPath.Text) ? null : LoadRsa(_pemPath.Text.Trim());
        RSA k = tmp ?? RequirePriv();
        string b64 = File.Exists(_cipherPath.Text.Trim()) ? File.ReadAllText(_cipherPath.Text.Trim()) : _cipherBox.Text;
        if (b64.Trim().Length == 0) throw new InvalidOperationException("Chưa có dữ liệu mã hoá (chọn file hoặc mã hoá ở bước trên).");
        byte[] plain = k.Decrypt(Convert.FromBase64String(b64.Trim()), RSAEncryptionPadding.OaepSHA256);

        string text;
        try { text = new UTF8Encoding(false, true).GetString(plain); }
        catch (DecoderFallbackException) { text = "(không phải văn bản UTF-8)"; }
        _plainBox.Text = $"{plain.Length} byte\r\nBase64: {Convert.ToBase64String(plain)}\r\nUTF-8 : {text}";

        bool same = plain.AsSpan().SequenceEqual(GetInput());
        _lblCmp.Text = same ? "✔ GIỐNG HỆT dữ liệu nguồn (so sánh từng byte)" : "✘ KHÁC dữ liệu nguồn";
        _lblCmp.ForeColor = same ? Good : Bad;
    }

    private static RSA LoadRsa(string path)
    {
        var k = RSA.Create();
        k.ImportFromPem(File.ReadAllText(path));
        return k;
    }

    private static void Pick(TextBox target, string filter)
    {
        using var dlg = new OpenFileDialog { Filter = filter };
        if (dlg.ShowDialog() == DialogResult.OK) target.Text = dlg.FileName;
    }

    // ======================================================================
    // TRANG 3 — TỐC ĐỘ
    // ======================================================================
    private Panel Build3()
    {
        var p = new Panel { BackColor = Bg };
        Header(p, "③  Tốc độ: public key (e nhỏ) so với private key (d to)", "Đo thời gian trung bình của từng phép toán, có thanh so sánh trực quan");
        Lbl(p, "Số lần lặp mỗi phép đo", 28, 96, Muted);
        _numIter = new NumericUpDown { Left = 28, Top = 120, Width = 120, Minimum = 10, Maximum = 5000, Value = 100, BackColor = InputBg, ForeColor = Fg };
        p.Controls.Add(_numIter);
        Btn(p, "⏱  Chạy đo tốc độ", 170, 116, 220, 36, () => { _ = Guard(BenchAsync); }, true);
        _benchBox = Box(p, 28, 172, 970, 584, multi: true, ro: true, size: 10f);
        _benchBox.WordWrap = false;
        _benchBox.ScrollBars = ScrollBars.Both;
        _benchBox.Text = "Cần private key (sinh khoá hoặc nhập ở trang ①), sau đó bấm “Chạy đo tốc độ”.\r\nGợi ý: thử lần lượt khoá 1024 / 2048 / 3072 / 4096 bit để thấy xu hướng.";
        return p;
    }

    private async Task BenchAsync()
    {
        RSA k = RequirePriv();
        int n = (int)_numIter.Value;
        _benchBox.Text = "Đang đo… (khoá lớn có thể mất vài giây)";
        _benchBox.Text = await Task.Run(() => Bench.Run(k, n));
    }

    // ======================================================================
    // TRANG 4 — SHA-256
    // ======================================================================
    private Panel Build4()
    {
        var p = new Panel { BackColor = Bg };
        Header(p, "④  Băm SHA-256 & hiệu ứng tuyết lở", "Sửa dữ liệu rất ít → quan sát xem bao nhiêu bit của giá trị băm thay đổi");
        Lbl(p, "DỮ LIỆU ĐẦU VÀO  (tự băm lại sau mỗi lần gõ)", 28, 96, Accent);
        _hashIn = Box(p, 28, 120, 970, 100, multi: true);
        _hashIn.Text = "Hello RSA 2026";

        Btn(p, "Đổi ký tự cuối (+1)", 28, 232, 190, 34, () =>
        {
            string t = _hashIn.Text;
            _hashIn.Text = t.Length == 0 ? "a" : t[..^1] + (char)(t[^1] + 1);
        });
        Btn(p, "Thêm một dấu cách", 226, 232, 190, 34, () => { _hashIn.Text += " "; });
        Btn(p, "Xoá ký tự cuối", 424, 232, 170, 34, () => { if (_hashIn.Text.Length > 0) _hashIn.Text = _hashIn.Text[..^1]; });

        Lbl(p, "SHA-256 TRƯỚC ĐÓ", 28, 282, Muted);
        _lblPrev = new Label { Left = 28, Top = 304, Width = 970, Height = 24, Font = new Font("Consolas", 11f), ForeColor = Muted };
        p.Controls.Add(_lblPrev);
        Lbl(p, "SHA-256 HIỆN TẠI  (ký tự màu cam = khác lần trước)", 28, 336, Accent);
        _rtbCur = new RichTextBox
        {
            Left = 28, Top = 358, Width = 970, Height = 30, ReadOnly = true, BorderStyle = BorderStyle.FixedSingle,
            BackColor = InputBg, ForeColor = Fg, Font = new Font("Consolas", 11f), ScrollBars = RichTextBoxScrollBars.None, WordWrap = false
        };
        p.Controls.Add(_rtbCur);
        _lblDiff = new Label { Left = 28, Top = 400, Width = 970, Height = 44, Font = new Font("Segoe UI Semibold", 12f), ForeColor = Good };
        p.Controls.Add(_lblDiff);

        _grid = new BitGrid { Left = 28, Top = 456 };
        p.Controls.Add(_grid);
        p.Controls.Add(new Label
        {
            Left = 372, Top = 462, Width = 626, Height = 290, ForeColor = Muted,
            Text = "CÁCH ĐỌC LƯỚI 16 × 16\r\n\r\n" +
                   "• Mỗi ô là 1 bit của giá trị băm 256 bit.\r\n" +
                   "• Ô sáng (tím) = bit 1,  ô tối = bit 0.\r\n" +
                   "• Viền cam = bit đã đổi so với lần băm trước.\r\n\r\n" +
                   "HIỆU ỨNG TUYẾT LỞ (avalanche)\r\n" +
                   "Một hàm băm tốt: đổi 1 bit đầu vào → khoảng một nửa số bit đầu ra thay đổi, " +
                   "phân bố đều, không thể đoán trước. Hãy thử nhấn các nút phía trên nhiều lần " +
                   "và xem “Trung bình” hội tụ về ≈ 50 %."
        });

        Rehash();
        _hashIn.TextChanged += (_, _) => Rehash();
        return p;
    }

    private void Rehash()
    {
        byte[] cur = SHA256.HashData(Encoding.UTF8.GetBytes(_hashIn.Text));
        _prevHash = _curHash;
        _curHash = cur;
        string hex = Convert.ToHexString(cur).ToLowerInvariant();
        string? prevHex = _prevHash == null ? null : Convert.ToHexString(_prevHash).ToLowerInvariant();

        _lblPrev.Text = prevHex ?? "(chưa có – hãy sửa dữ liệu để so sánh)";
        _rtbCur.Text = hex;
        int hexDiff = 0;
        if (prevHex != null)
        {
            for (int i = 0; i < 64; i++)
            {
                if (hex[i] == prevHex[i]) continue;
                hexDiff++;
                _rtbCur.Select(i, 1);
                _rtbCur.SelectionColor = Warn;
            }
        }
        _rtbCur.Select(0, 0);
        _grid.SetHashes(cur, _prevHash);

        if (_prevHash == null) { _lblDiff.Text = ""; return; }
        int bits = HashUtil.Hamming(cur, _prevHash);
        _diffPct.Add(bits / 2.56);
        _lblDiff.Text = $"Thay đổi {bits}/256 bit ({bits / 2.56:F1} %) · {hexDiff}/64 ký tự hex khác\r\n" +
                        $"Trung bình sau {_diffPct.Count} lần sửa: {_diffPct.Average():F1} %   (lý tưởng ≈ 50 %)";
    }

    // ======================================================================
    // TRANG 5 — CHỮ KÝ SỐ
    // ======================================================================
    private Panel Build5()
    {
        var p = new Panel { BackColor = Bg };
        Header(p, "⑤  Chữ ký số: cùng dữ liệu, cùng người ký, chữ ký khác nhau", "So sánh PKCS#1 v1.5 (xác định) với RSA-PSS và Nonce+PKCS#1 (ngẫu nhiên hoá)");
        Lbl(p, "DỮ LIỆU CẦN KÝ", 28, 96, Accent);
        _sigIn = Box(p, 28, 120, 970, 80, multi: true);
        _sigIn.Text = "Chuyển khoản 1.000.000 VND cho Nguyễn Văn A";
        Btn(p, "✍  KÝ 5 LẦN MỖI PHƯƠNG PHÁP & XÁC MINH", 28, 212, 470, 42, () => Safe(RunSign), true);
        Lbl(p, "Chữ ký = RSA(private key, SHA-256(dữ liệu)).  Cột cuối: xác minh với dữ liệu gốc / dữ liệu bị sửa 1 bit.", 28, 266, Muted);
        _sigOut = Box(p, 28, 292, 970, 464, multi: true, ro: true, size: 9.5f);
        _sigOut.WordWrap = false;
        _sigOut.ScrollBars = ScrollBars.Both;
        return p;
    }

    private void RunSign()
    {
        RSA priv = RequirePriv();
        RSA pub = RequirePub();
        byte[] data = Encoding.UTF8.GetBytes(_sigIn.Text);
        if (data.Length == 0) throw new InvalidOperationException("Hãy nhập dữ liệu cần ký.");
        byte[] bad = (byte[])data.Clone();
        bad[0] ^= 1;

        var sb = new StringBuilder();
        sb.AppendLine($"SHA-256(dữ liệu) = {Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant()}");
        sb.AppendLine($"Khoá ký          = RSA-{priv.KeySize}");

        void Round(string title, Func<string> sign, Func<string, byte[], bool> verify)
        {
            sb.AppendLine();
            sb.AppendLine("━━ " + title);
            var set = new HashSet<string>();
            for (int i = 1; i <= 5; i++)
            {
                string s = sign();
                set.Add(s);
                string shown = s.Length > 48 ? s[..36] + "…" + s[^8..] : s;
                string ok = verify(s, data) ? "✔ hợp lệ" : "✘ lỗi";
                string tamper = verify(s, bad) ? "✔ (SAI!)" : "✘ bị từ chối (đúng)";
                sb.AppendLine($"  #{i}  {shown}   gốc: {ok}   sửa 1 bit: {tamper}");
            }
            sb.AppendLine($"  → {set.Count}/5 chữ ký khác nhau   {(set.Count == 5 ? "✔ ĐẠT yêu cầu" : "✘ KHÔNG đạt yêu cầu")}");
        }

        Round("A) RSASSA-PKCS1-v1_5 — thuật toán XÁC ĐỊNH",
            () => Convert.ToBase64String(Signer.SignPkcs1(priv, data)),
            (s, d) => Signer.Verify(pub, d, Convert.FromBase64String(s), RSASignaturePadding.Pkcs1));

        Round("B) RSASSA-PSS — thêm SALT ngẫu nhiên (khuyến nghị)",
            () => Convert.ToBase64String(Signer.SignPss(priv, data)),
            (s, d) => Signer.Verify(pub, d, Convert.FromBase64String(s), RSASignaturePadding.Pss));

        Round("C) Nonce 16 byte ‖ dữ liệu → băm → ký PKCS#1 (gửi kèm nonce)",
            () => Signer.SignNonce(priv, data),
            (s, d) => Signer.VerifyNonce(pub, d, s));

        _sigOut.Text = sb.ToString();
    }

    // ======================================================================
    // TIỆN ÍCH GIAO DIỆN
    // ======================================================================
    private static string Crlf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");

    private void Safe(Action a)
    {
        try { a(); } catch (Exception ex) { Fail(ex); }
    }

    private async Task Guard(Func<Task> work)
    {
        if (_busy) return;
        _busy = true;
        UseWaitCursor = true;
        try { await work(); }
        catch (Exception ex) { Fail(ex); }
        finally { _busy = false; UseWaitCursor = false; }
    }

    private static void Fail(Exception ex) =>
        MessageBox.Show(ex.Message, "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);

    private static void Header(Control p, string title, string sub)
    {
        p.Controls.Add(new Label { Text = title, Font = new Font("Segoe UI Semibold", 17f), ForeColor = Fg, Left = 26, Top = 14, AutoSize = true });
        p.Controls.Add(new Label { Text = sub, ForeColor = Muted, Left = 30, Top = 56, AutoSize = true });
    }

    private static Label Lbl(Control parent, string text, int x, int y, Color color)
    {
        var l = new Label { Text = text, Left = x, Top = y, AutoSize = true, ForeColor = color };
        parent.Controls.Add(l);
        return l;
    }

    private static TextBox Box(Control parent, int x, int y, int w, int h, bool multi = false, bool ro = false, float size = 10f)
    {
        var t = new TextBox
        {
            Left = x, Top = y, Width = w, Height = h, Multiline = multi, ReadOnly = ro,
            BorderStyle = BorderStyle.FixedSingle, BackColor = InputBg, ForeColor = Fg, Font = new Font("Consolas", size)
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
            BackColor = primary ? Accent : Color.FromArgb(40, 36, 66),
            ForeColor = primary ? Color.FromArgb(20, 12, 40) : Fg,
            Font = new Font("Segoe UI Semibold", 9.5f)
        };
        b.FlatAppearance.BorderSize = 0;
        b.Click += (_, _) => onClick();
        parent.Controls.Add(b);
        return b;
    }
}
