# Hộp thoại chọn thư mục; in đường dẫn ra stdout (rỗng nếu huỷ).
$ErrorActionPreference = 'Stop'
try {
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Chọn thư mục dự án cần quét bảo mật'
$dialog.ShowNewFolderButton = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.SelectedPath)
}
} catch { exit 1 }
