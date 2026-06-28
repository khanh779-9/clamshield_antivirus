using System;
using System.IO;
using System.Runtime.InteropServices;

namespace clamshield_antivirus.Services;

public class ContextMenuService
{
    private const string RegPath = @"Software\Classes\*\shell\ClamUI";
    private const string RegDirPath = @"Software\Classes\Directory\shell\ClamUI";
    private const string RegDrivePath = @"Software\Classes\Drive\shell\ClamUI";
    private const string CommandKey = "command";
    private const string MenuName = "Scan with ClamUI";
    private const string IconKey = "Icon";

    public bool IsRegistered()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath);
        return key != null;
    }

    public void Register()
    {
        string exePath = Environment.ProcessPath ?? AssemblyLocation();

        RegisterVerb(RegPath, exePath);
        RegisterVerb(RegDirPath, exePath);
        RegisterVerb(RegDrivePath, exePath);
    }

    public void Unregister()
    {
        try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(RegPath, false); } catch { }
        try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(RegDirPath, false); } catch { }
        try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(RegDrivePath, false); } catch { }
    }

    private static void RegisterVerb(string path, string exePath)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(path);
        if (key == null) return;
        key.SetValue(null, MenuName);
        key.SetValue(IconKey, exePath + ",0");

        using var cmdKey = key.CreateSubKey(CommandKey);
        cmdKey?.SetValue(null, $"\"{exePath}\" --scan \"%1\"");
    }

    private static string AssemblyLocation()
    {
        var asm = System.Reflection.Assembly.GetEntryAssembly();
        return asm?.Location ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "clamshield_antivirus.exe");
    }
}
