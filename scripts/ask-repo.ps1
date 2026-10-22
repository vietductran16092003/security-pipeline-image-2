# Hộp thoại nhập link repo cần kiểm tra.
# Có -OutFile: ghi link vào file đó (UTF-8, không BOM) để cmd KHÔNG phải xử lý link trên dòng lệnh.
# Không có -OutFile: in link ra stdout. Huỷ: không ghi gì, thoát 0. Lỗi: thoát 1.
param([string]$OutFile = '')
$ErrorActionPreference = 'Stop'
try {
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Kiểm tra repo lạ trước khi tải'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(520, 150)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = "Dán link repo cần kiểm tra.`nVí dụ: owner/repo hoặc https://gitlab.com/nhom/du-an"
$label.SetBounds(12, 12, 496, 44)
$box = New-Object System.Windows.Forms.TextBox
$box.SetBounds(12, 62, 496, 24)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Kiểm tra'
$ok.SetBounds(332, 105, 84, 28)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Huỷ'
$cancel.SetBounds(424, 105, 84, 28)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.AcceptButton = $ok
$form.CancelButton = $cancel
$form.Controls.AddRange(@($label, $box, $ok, $cancel))
if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $text = $box.Text.Trim()
    if ($text.Length -gt 0) {
        if ($OutFile) {
            [System.IO.File]::WriteAllText($OutFile, $text, (New-Object System.Text.UTF8Encoding($false)))
        } else {
            [Console]::Out.Write($text)
        }
    }
}
} catch { exit 1 }