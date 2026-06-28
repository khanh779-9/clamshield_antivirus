using System;
using System.IO;

namespace clamshield_antivirus.Services;

public static class BZip2Decoder
{
    private const long BlockMagic = 0x314159265359;
    private const long StreamMagic = 0x177245385090;

    public static byte[] Decompress(byte[] input)
    {
        var reader = new BitReader(input);
        return Decompress(reader);
    }

    private static byte[] Decompress(BitReader reader)
    {
        int b = reader.ReadByte();
        int z = reader.ReadByte();
        if (b != 'B' || z != 'Z')
            throw new InvalidDataException("Not a BZip2 file");

        int h = reader.ReadByte();
        if (h != 'h')
            throw new InvalidDataException("Unsupported BZip2 variant");

        int blockSize100k = reader.ReadByte() - '0';
        if (blockSize100k < 1 || blockSize100k > 9)
            throw new InvalidDataException("Invalid BZip2 block size");

        using var output = new MemoryStream();

        int blockIndex = 0;
        while (true)
        {
            if ((int)reader.ReadBits(1) != 0) break;
            blockIndex++;

            long blockMagic = reader.ReadBits(48);
            if (blockMagic != BlockMagic)
                throw new InvalidDataException("Invalid BZip2 block magic");

            int blockCrc = (int)reader.ReadBits(32);
            bool randomized = reader.ReadBits(1) != 0;
            int origPtr = (int)reader.ReadBits(24);

            bool[] inUse = new bool[256];
            int inUse16 = (int)reader.ReadBits(16);
            int usedTotal = 0;
            for (int i = 0; i < 16; i++)
            {
                if ((inUse16 & (1 << (15 - i))) != 0)
                {
                    int inUseBitField = (int)reader.ReadBits(16);
                    for (int j = 0; j < 16; j++)
                    {
                        if ((inUseBitField & (1 << (15 - j))) != 0)
                        {
                            inUse[usedTotal] = true;
                            usedTotal++;
                        }
                    }
                }
            }

            int numSymbols = usedTotal + 2;
            int numTrees = (int)reader.ReadBits(3);
            int numSelectors = (int)reader.ReadBits(15);

            byte[] selectorMtf = new byte[numSelectors];
            for (int i = 0; i < numSelectors; i++)
            {
                int j = 0;
                while (reader.ReadBits(1) != 0) j++;
                selectorMtf[i] = (byte)j;
            }

            byte[] selector = new byte[numSelectors];
            for (int i = 0; i < numSelectors; i++)
            {
                int j = i;
                int mtfVal = selectorMtf[i];
                while (mtfVal > 0) { var tmp = selector[j]; selector[j] = selector[j - 1]; selector[j - 1] = tmp; j--; mtfVal--; }
                selector[i] = selector[i - selectorMtf[i]];
            }

            var trees = new HuffmanTree[numTrees];
            for (int t = 0; t < numTrees; t++)
            {
                int alphaSize = numSymbols;
                int[] len = new int[alphaSize];
                int currentLen = (int)reader.ReadBits(5);
                for (int i = 0; i < alphaSize; i++)
                {
                    while (true)
                    {
                        if ((int)reader.ReadBits(1) == 0) break;
                        currentLen += ((int)reader.ReadBits(1) == 0) ? -1 : 1;
                    }
                    len[i] = currentLen;
                }
                trees[t] = new HuffmanTree(len);
            }

            var symbols = new RunLengthDecoder(numSymbols - 2);
            int nextSym;
            int treeIndex = 0;
            int selectorIndex = 0;
            while ((nextSym = DecodeSymbol(reader, trees[selector[selectorIndex]], numSymbols)) != numSymbols - 1)
            {
                treeIndex++;
                if (treeIndex >= 50)
                {
                    treeIndex = 0;
                    selectorIndex++;
                }

                if (nextSym < 0) break;
                symbols.Add(nextSym);
            }

            byte[] mtfData = symbols.ToArray();

            int size = mtfData.Length;
            byte[] unMtf = new byte[size];
            byte[] mtfTable = new byte[256];
            int mtfTableSize = numSymbols - 2;
            int usedCount = 0;
            for (int i = 0; i < 256; i++)
            {
                if (inUse[i])
                {
                    mtfTable[usedCount] = (byte)i;
                    usedCount++;
                }
            }

            for (int i = 0; i < size; i++)
            {
                int sym = mtfData[i];
                if (sym == 0)
                {
                    unMtf[i] = mtfTable[0];
                }
                else
                {
                    byte val = mtfTable[sym];
                    for (int j = sym; j > 0; j--)
                        mtfTable[j] = mtfTable[j - 1];
                    mtfTable[0] = val;
                    unMtf[i] = val;
                }
            }

            byte[] bwData = InverseBWT(unMtf, origPtr);

            byte[] rleData = new byte[bwData.Length * 2];
            int rleIdx = 0, srcIdx = 0;
            while (srcIdx < bwData.Length)
            {
                byte ch = bwData[srcIdx];
                if (srcIdx + 4 < bwData.Length &&
                    bwData[srcIdx] == bwData[srcIdx + 1] &&
                    bwData[srcIdx] == bwData[srcIdx + 2] &&
                    bwData[srcIdx] == bwData[srcIdx + 3])
                {
                    int runLen = bwData[srcIdx + 4];
                    srcIdx += 5;
                    for (int k = 0; k < 4 + runLen; k++)
                    {
                        if (rleIdx >= rleData.Length)
                            Array.Resize(ref rleData, rleData.Length * 2);
                        rleData[rleIdx++] = ch;
                    }
                }
                else
                {
                    if (rleIdx >= rleData.Length)
                        Array.Resize(ref rleData, rleData.Length * 2);
                    rleData[rleIdx++] = ch;
                    srcIdx++;
                }
            }

            Array.Resize(ref rleData, rleIdx);
            output.Write(rleData, 0, rleData.Length);
        }

        int streamCrc = (int)reader.ReadBits(32);
        return output.ToArray();
    }

    private static int DecodeSymbol(BitReader reader, HuffmanTree tree, int numSymbols)
    {
        int node = 0;
        while (!tree.IsLeaf[node])
        {
            node = tree.Child[node, (int)reader.ReadBits(1)];
        }
        return tree.Symbol[node];
    }

    private static byte[] InverseBWT(byte[] data, int origPtr)
    {
        int n = data.Length;
        int[] count = new int[256];
        for (int i = 0; i < n; i++)
            count[data[i]]++;

        int sum = 0;
        int[] baseC = new int[256];
        for (int i = 0; i < 256; i++)
        {
            baseC[i] = sum;
            sum += count[i];
        }

        int[] next = new int[n];
        int[] cum = new int[256];
        Array.Copy(baseC, cum, 256);

        for (int i = 0; i < n; i++)
        {
            int ch = data[i];
            next[cum[ch]] = i;
            cum[ch]++;
        }

        byte[] result = new byte[n];
        int idx = next[origPtr];
        for (int i = 0; i < n; i++)
        {
            result[i] = data[idx];
            idx = next[idx];
        }
        return result;
    }

    private class BitReader
    {
        private readonly byte[] _data;
        private int _pos;
        private int _bits;

        public BitReader(byte[] data)
        {
            _data = data;
            _pos = 0;
            _bits = 0;
        }

        public int ReadByte() => _pos < _data.Length ? _data[_pos++] : throw new EndOfStreamException();

        public long ReadBits(int count)
        {
            long result = 0;
            for (int i = 0; i < count; i++)
            {
                result = (result << 1) | (long)((_data[_pos] >> (7 - _bits)) & 1);
                _bits++;
                if (_bits >= 8)
                {
                    _bits = 0;
                    _pos++;
                }
            }
            return result;
        }
    }

    private class HuffmanTree
    {
        public int[] Symbol;
        public int[,] Child;
        public bool[] IsLeaf;

        public HuffmanTree(int[] lens)
        {
            int maxLen = 0;
            for (int i = 0; i < lens.Length; i++)
                if (lens[i] > maxLen) maxLen = lens[i];

            int limit = 1 << maxLen;
            int maxNodes = (lens.Length * 2) + 2;
            Symbol = new int[maxNodes];
            Child = new int[maxNodes, 2];
            IsLeaf = new bool[maxNodes];

            for (int i = 0; i < maxNodes; i++)
            {
                Child[i, 0] = -1;
                Child[i, 1] = -1;
            }

            int nodeCount = 1;
            for (int i = 0; i < lens.Length; i++)
            {
                if (lens[i] <= 0) continue;
                int node = 0;
                for (int b = 0; b < lens[i]; b++)
                {
                    int bit = (i >> (lens[i] - 1 - b)) & 1;
                    if (Child[node, bit] < 0)
                    {
                        Child[node, bit] = nodeCount++;
                    }
                    node = Child[node, bit];
                }
                Symbol[node] = i;
                IsLeaf[node] = true;
            }
        }
    }

    private class RunLengthDecoder
    {
        private readonly int _maxSym;
        private readonly System.Collections.Generic.List<int> _data = new();
        private int _lastSym = -1;
        private int _runCount;

        public RunLengthDecoder(int maxSym)
        {
            _maxSym = maxSym;
        }

        public void Add(int sym)
        {
            if (sym == _maxSym + 1)
            {
                _runCount++;
                return;
            }

            if (_runCount > 0)
            {
                for (int k = 0; k < _runCount; k++)
                {
                    _data.Add(_lastSym);
                    _data.Add(sym);
                }
                _runCount = 0;
            }
            else
            {
                _data.Add(sym);
            }

            _lastSym = sym;
        }

        public byte[] ToArray()
        {
            var result = new byte[_data.Count];
            for (int i = 0; i < _data.Count; i++)
                result[i] = (byte)_data[i];
            return result;
        }
    }
}
