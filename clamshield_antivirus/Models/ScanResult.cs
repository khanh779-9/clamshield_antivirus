using System;
using System.Collections.Generic;

namespace clamshield_antivirus.Models;

public class ThreatDetail
{
    public string ThreatName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string Severity { get; set; } = "Low";
    public string Status { get; set; } = "Detected";
    public string? HashType { get; set; }
    public string? FileHash { get; set; }
    public string? MatchType { get; set; }
}

public class ScanResult
{
    public int FilesScanned { get; set; }
    public int DirectoriesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public TimeSpan Duration { get; set; }
    public string ScanPath { get; set; } = string.Empty;
    public string Status { get; set; } = "Clean";
    public List<ThreatDetail> Threats { get; set; } = new();
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public string RawLog { get; set; } = string.Empty;
    public int TotalSignaturesLoaded { get; set; }
    public long TotalBytesScanned { get; set; }
}

public class DbVersionInfo
{
    public string DatabaseName { get; set; } = string.Empty;
    public int Version { get; set; }
    public int SignatureCount { get; set; }
    public DateTime BuildTime { get; set; }
    public string Builder { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public bool IsInstalled => !string.IsNullOrEmpty(FilePath) && System.IO.File.Exists(FilePath);
}
