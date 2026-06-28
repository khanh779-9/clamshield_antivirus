using System;

namespace clamshield_antivirus.Models;

public class QuarantineEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ThreatName { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinePath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public DateTime QuarantineDate { get; set; } = DateTime.Now;
}
