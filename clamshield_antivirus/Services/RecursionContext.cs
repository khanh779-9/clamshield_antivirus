using System;

namespace clamshield_antivirus.Services;

public class RecursionContext
{
    private int _currentDepth;
    private int _totalFiles;
    private long _totalBytes;
    private int _totalArchives;

    public int MaxDepth { get; }
    public int MaxFiles { get; }
    public long MaxScanSize { get; }
    public long MaxFileSize { get; }

    public int CurrentDepth => _currentDepth;
    public int TotalFiles => _totalFiles;
    public long TotalBytes => _totalBytes;
    public int TotalArchives => _totalArchives;

    public bool LimitExceeded =>
        _currentDepth > MaxDepth ||
        _totalFiles > MaxFiles ||
        _totalBytes > MaxScanSize;

    public RecursionContext(int maxDepth, int maxFiles, long maxScanSize, long maxFileSize)
    {
        MaxDepth = maxDepth;
        MaxFiles = maxFiles;
        MaxScanSize = maxScanSize;
        MaxFileSize = maxFileSize;
    }

    public IDisposable EnterArchive()
    {
        _currentDepth++;
        _totalArchives++;
        return new RecursionScope(this);
    }

    public bool CanScanFile(long fileSize)
    {
        if (_currentDepth > MaxDepth) return false;
        if (_totalFiles >= MaxFiles) return false;
        if (_totalBytes + fileSize > MaxScanSize) return false;
        if (fileSize > MaxFileSize) return false;
        return true;
    }

    public void RecordFile(long size)
    {
        _totalFiles++;
        _totalBytes += size;
    }

    private class RecursionScope : IDisposable
    {
        private readonly RecursionContext _ctx;
        private bool _disposed;

        public RecursionScope(RecursionContext ctx)
        {
            _ctx = ctx;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _ctx._currentDepth--;
                _disposed = true;
            }
        }
    }
}
