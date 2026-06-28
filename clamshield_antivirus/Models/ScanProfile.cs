using System.Collections.Generic;

namespace clamshield_antivirus.Models;

public class ScanProfile
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> TargetPaths { get; set; } = new();
    public List<string> ExclusionPatterns { get; set; } = new();
    public bool DeepScan { get; set; }
    public bool AutoQuarantine { get; set; }
}
