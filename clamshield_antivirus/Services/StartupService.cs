using System;
using Microsoft.Win32;

namespace clamshield_antivirus.Services;

public class StartupService
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "ClamUI";

    public bool IsRegistered()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        if (key == null) return false;
        var val = key.GetValue(AppName) as string;
        return !string.IsNullOrEmpty(val);
    }

    public void Register()
    {
        string exePath = Environment.ProcessPath ?? AssemblyLocation();
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        key?.SetValue(AppName, $"\"{exePath}\"");
    }

    public void Unregister()
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        key?.DeleteValue(AppName, false);
    }

    private static string AssemblyLocation()
    {
        var asm = System.Reflection.Assembly.GetEntryAssembly();
        return asm?.Location ?? AppDomain.CurrentDomain.BaseDirectory;
    }
}
