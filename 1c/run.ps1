<#
Запуск обработки «Обезличивание данных» на файловой базе (ENTERPRISE /Execute), результат - в файл отчета.
Пример:
  .\run.ps1 -BasePath D:\BASES\1C_BK_test -User Администратор -Profile KZ -Mode ИНВЕНТАРИЗАЦИЯ -Report report.txt
Запуск на копии базы, не на рабочей. Таймаут обязателен: клиент, зависший на диалоге, снимается принудительно.
#>
param(
    [Parameter(Mandatory)][string]$BasePath,
    [string]$User = "",
    [string]$Password = "",
    [ValidateSet("KZ", "RU")][string]$Profile = "KZ",
    [string]$Mode = "ИНВЕНТАРИЗАЦИЯ",
    [Parameter(Mandatory)][string]$Report,
    [string]$Rules = "",
    [string]$Secret = "",
    [string]$Snapshot = "",
    [switch]$ConfirmTestCopy,
    [switch]$Repeat,
    [string]$Objects = "",
    [string]$Keep = "",
    [string]$Users = "",
    [string]$Epf = "",
    [string]$Platform = "C:\Program Files\1cv8\8.3.27.1989\bin\1cv8.exe",
    [int]$TimeoutSec = 900
)
$ErrorActionPreference = "Stop"
if (-not $Epf) { $Epf = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "build\ОбезличиваниеДанных.epf" }
if (-not (Test-Path (Join-Path $BasePath "1Cv8.1CD"))) { throw "В папке нет файловой базы: $BasePath" }
if (Test-Path $Report) { Remove-Item $Report -Force }
$reportFull = [IO.Path]::GetFullPath($Report)
$cParam = "ПРОФИЛЬ=$Profile;РЕЖИМ=$Mode;ОТЧЕТ=$reportFull"
if ($Rules) { $cParam += ";ПРАВИЛА=" + [IO.Path]::GetFullPath($Rules) }
if ($Secret) { $cParam += ";СЕКРЕТ=$Secret" }
if ($Snapshot) { $cParam += ";СНИМОК=" + [IO.Path]::GetFullPath($Snapshot) }
if ($ConfirmTestCopy) { $cParam += ";ПОДТВЕРЖДЕНИЕ=ТЕСТОВАЯ_КОПИЯ" }
if ($Repeat) { $cParam += ";ПОВТОР=ДА" }
if ($Objects) { $cParam += ";ОБЪЕКТЫ=$Objects" }
if ($Keep) { $cParam += ";ОСТАВИТЬ=$Keep" }
if ($Users) { $cParam += ";ПОЛЬЗОВАТЕЛИ=$Users" }
$cmdArgs = @("ENTERPRISE", "/F`"$BasePath`"", "/DisableStartupDialogs", "/DisableUnsafeActionProtection", "/Execute`"$Epf`"",
    "/C`"$cParam`"")
if ($User) { $cmdArgs += "/N`"$User`"" }
if ($Password) { $cmdArgs += "/P`"$Password`"" }
$proc = Start-Process -FilePath $Platform -ArgumentList $cmdArgs -PassThru
if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
    & taskkill /PID $proc.Id /T /F | Out-Null
    throw "Таймаут $TimeoutSec с: клиент снят принудительно (возможно, диалог платформы)"
}
"Код возврата: $($proc.ExitCode)"
if (Test-Path $reportFull) { "Отчет: $reportFull" } else { throw "Отчет не создан: обработка не отработала" }
