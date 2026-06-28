namespace clamshield_antivirus.Models;

public class ComponentStatus
{
    public string Name { get; set; } = string.Empty;
    public string ComponentId { get; set; } = string.Empty; // clamscan, freshclam, clamd, clamdscan
    public bool IsInstalled { get; set; }
    public string Version { get; set; } = "Not installed";
    public string Description { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string Status { get => IsInstalled ? "installed" : "notinstalled"; }
}
