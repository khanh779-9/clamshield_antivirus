using System;

namespace clamshield_antivirus.Models;

public class LogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Type { get; set; } = "Scan"; // Scan, Update
    public string Summary { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string Status { get; set; } = "Success"; // Success, Warning, Fail
    public string ScanPath { get; set; } = string.Empty;
}
