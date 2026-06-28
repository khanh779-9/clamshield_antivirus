using System;
using System.Diagnostics;
using System.IO;

namespace clamshield_antivirus.Services;

public class ScheduleService
{
    private const string TaskName = "ClamUI Daily Scan";

    public bool IsScheduled()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks", $"/query /tn \"{TaskName}\" /fo LIST")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return output.Contains(TaskName);
        }
        catch { return false; }
    }

    public void ScheduleDaily(string time)
    {
        string exePath = Environment.ProcessPath ?? AssemblyLocation();
        string taskCmd = $"/create /tn \"{TaskName}\" /tr \"\\\"{exePath}\\\" --scan\" /sc daily /st {time} /f";
        RunSchTasks(taskCmd);
    }

    public void ScheduleWeekly(string day, string time)
    {
        string exePath = Environment.ProcessPath ?? AssemblyLocation();
        string taskCmd = $"/create /tn \"{TaskName}\" /tr \"\\\"{exePath}\\\" --scan\" /sc weekly /d {day} /st {time} /f";
        RunSchTasks(taskCmd);
    }

    public void Unschedule()
    {
        RunSchTasks($"/delete /tn \"{TaskName}\" /f");
    }

    private static void RunSchTasks(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks", arguments)
            {
                UseShellExecute = true,
                CreateNoWindow = true,
                Verb = "runas"
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(30000);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"schtasks failed: {ex.Message}");
        }
    }

    private static string AssemblyLocation()
    {
        var asm = System.Reflection.Assembly.GetEntryAssembly();
        return asm?.Location ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "clamshield_antivirus.exe");
    }
}
