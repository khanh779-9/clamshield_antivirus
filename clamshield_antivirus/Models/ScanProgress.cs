namespace clamshield_antivirus.Models;

public class ScanProgress
{
    public string CurrentFile { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public double ProgressPercentage { get; set; }
    public bool IsIndeterminate { get; set; } = true;
    public string StatusText { get; set; } = string.Empty;
    public long BytesScanned { get; set; }
    public int ThreatsFoundSoFar { get; set; }
}
