using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Color = System.Windows.Media.Color;

namespace clamshield_antivirus.Converters;

/// <summary>
/// Converts boolean to Visibility (true → Visible, false → Collapsed).
/// </summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is Visibility v && v == Visibility.Visible;
    }
}

/// <summary>
/// Converts boolean to Visibility (true → Collapsed, false → Visible).
/// </summary>
public class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Collapsed : Visibility.Visible;
        return Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is Visibility v && v == Visibility.Collapsed;
    }
}

/// <summary>
/// Converts file size in bytes to human-readable string.
/// </summary>
public class FileSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is long size)
            return FormatFileSize(size);
        if (value is int intSize)
            return FormatFileSize(intSize);
        return "0 B";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }

    public static string FormatFileSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}

public class StatusToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string? status = null;

        // Support numeric threat counts: 0 = clean, >0 = infected
        if (value is int intVal)
        {
            status = intVal > 0 ? "infected" : "clean";
        }
        else if (value is long longVal)
        {
            status = longVal > 0 ? "infected" : "clean";
        }
        else if (value != null && double.TryParse(value.ToString(), out double doubleVal))
        {
            status = doubleVal > 0 ? "infected" : "clean";
        }
        else
        {
            status = value?.ToString()?.ToLowerInvariant();
        }

        var baseColor = status switch
        {
            "pass" or "installed" or "success" or "clean" or "protected" or "safe" =>
                Color.FromRgb(0xA6, 0xE3, 0xA1), // Green
            "warning" or "partial" or "cancelled" =>
                Color.FromRgb(0xF9, 0xE2, 0xAF), // Amber
            "fail" or "error" or "infected" or "notinstalled" or "danger" =>
                Color.FromRgb(0xF3, 0x8B, 0xA8), // Red
            "scanning" or "updating" or "running" or "loading" =>
                Color.FromRgb(0x89, 0xB4, 0xFA), // Blue
            _ => Color.FromRgb(0xA6, 0xAD, 0xC8)  // Gray
        };

        var paramStr = parameter?.ToString()?.ToLowerInvariant();
        if (paramStr == "badge_bg")
        {
            // 15% opacity background for modern badges
            return new SolidColorBrush(Color.FromArgb(38, baseColor.R, baseColor.G, baseColor.B));
        }
        else if (paramStr == "card_border")
        {
            // 35% opacity border for badges or cards
            return new SolidColorBrush(Color.FromArgb(89, baseColor.R, baseColor.G, baseColor.B));
        }
        else if (paramStr == "card_bg")
        {
            // 8% opacity background for larger status cards
            return new SolidColorBrush(Color.FromArgb(20, baseColor.R, baseColor.G, baseColor.B));
        }
        else if (paramStr == "badge_fg")
        {
            // 100% opacity foreground color
            return new SolidColorBrush(baseColor);
        }

        return new SolidColorBrush(baseColor);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts status string to a status icon character (Unicode).
/// </summary>
public class StatusToIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var status = value?.ToString()?.ToLowerInvariant();
        return status switch
        {
            "pass" or "installed" or "success" or "clean" => "✓",
            "warning" or "partial" or "cancelled" => "⚠",
            "fail" or "error" or "infected" or "notinstalled" => "✗",
            "scanning" or "updating" => "⟳",
            _ => "?"
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts a non-null/non-empty string to Visibility.Visible, else Collapsed.
/// </summary>
public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return string.IsNullOrWhiteSpace(value?.ToString()) ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts int count > 0 to Visibility.Visible.
/// </summary>
public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int count)
            return count > 0 ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Inverts a boolean value.
/// </summary>
public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b) return !b;
        return true;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b) return !b;
        return false;
    }
}

/// <summary>
/// Check equality between a bound string property and a target string parameter.
/// </summary>
public class TimeframeEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value?.ToString() == parameter?.ToString();
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b && b ? parameter?.ToString() ?? string.Empty : Binding.DoNothing;
    }
}

/// <summary>
/// Checks if the string representation of bound value contains the parameter string.
/// </summary>
public class StringContainsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string? valStr = value?.ToString();
        string? paramStr = parameter?.ToString();
        if (valStr == null || paramStr == null) return false;
        return valStr.Contains(paramStr, StringComparison.OrdinalIgnoreCase);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts HasIssues (bool) to a background color brush for the summary card.
/// true (has issues) → warm amber; false (all clean) → success green.
/// </summary>
public class IssuesToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool hasIssues)
            return hasIssues
                ? new SolidColorBrush(Color.FromArgb(20, 0xF9, 0xE2, 0xAF))
                : new SolidColorBrush(Color.FromArgb(20, 0xA6, 0xE3, 0xA1));
        return new SolidColorBrush(Color.FromArgb(20, 0xA6, 0xAD, 0xC8));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts HasIssues (bool) to an icon emoji for the summary card.
/// true (has issues) → "⚠"; false (all clean) → "✓".
/// </summary>
public class IssuesToIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool hasIssues)
            return hasIssues ? "⚠" : "✓";
        return "?";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converts AuditItem.Status to Visibility for the suggestion/fix section.
/// Visible only for "warning" or "fail" status (not "pass").
/// </summary>
public class AuditWarningToVisConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var status = value?.ToString()?.ToLowerInvariant();
        return status is "warning" or "fail" ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
