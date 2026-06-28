using System;
using System.IO;

namespace clamshield_antivirus.Services;

public static class XzDecoder
{
    public static byte[] Decompress(byte[] input)
    {
        int pos = 0;
        if (input.Length < 12) throw new InvalidDataException("Not an XZ file");
        if (input[0] != 0xFD || input[1] != 0x37 || input[2] != 0x7A || input[3] != 0x58)
            throw new InvalidDataException("Invalid XZ magic");

        pos = 6;
        int streamFlags = (input[pos++] << 8) | input[pos++];

        using var output = new MemoryStream();

        while (pos + 4 <= input.Length)
        {
            int blockSize = (input[pos] << 24) | (input[pos + 1] << 16) | (input[pos + 2] << 8) | input[pos + 3];
            pos += 4;

            if (blockSize == 0)
            {
                pos += 4;
                break;
            }

            if (pos + blockSize > input.Length) break;

            var blockData = new byte[blockSize];
            Array.Copy(input, pos, blockData, 0, blockSize);
            pos += blockSize;

            int blockCrc = (input[pos] << 24) | (input[pos + 1] << 16) | (input[pos + 2] << 8) | input[pos + 3];
            pos += 4;

            byte[] blockResult = DecompressBlock(blockData);
            output.Write(blockResult, 0, blockResult.Length);
        }

        return output.ToArray();
    }

    private static byte[] DecompressBlock(byte[] data)
    {
        int pos = 0;
        if (pos >= data.Length) throw new InvalidDataException("Empty block");

        int blockFlags = data[pos++];
        int numFilters = blockFlags & 0x03;

        if (blockFlags == 0x00)
        {
            int size = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
            var result = new byte[size];
            Array.Copy(data, pos, result, 0, Math.Min(size, data.Length - pos));
            return result;
        }

        int filterId;
        for (int f = 0; f < numFilters && pos < data.Length; f++)
        {
            filterId = (int)ReadVarInt(data, ref pos);
            int propsSize = (int)ReadVarInt(data, ref pos);
            pos += propsSize;
        }

        int lzma2Size = data.Length - pos - 4;
        if (lzma2Size < 0) lzma2Size = 0;

        var lzma2Data = new byte[lzma2Size];
        Array.Copy(data, pos, lzma2Data, 0, lzma2Size);

        return DecompressLzma2(lzma2Data);
    }

    private static long ReadVarInt(byte[] data, ref int pos)
    {
        long result = 0;
        for (int i = 0; i < 9; i++)
        {
            if (pos >= data.Length) break;
            byte b = data[pos++];
            result |= (long)(b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) break;
        }
        return result;
    }

    private static byte[] DecompressLzma2(byte[] data)
    {
        using var output = new MemoryStream();
        int pos = 0;

        while (pos < data.Length)
        {
            byte ctrl = data[pos++];

            if (ctrl == 0x00) break;

            if (ctrl == 0x01 || ctrl == 0x02)
            {
                int dictSize = 0;
                if (ctrl == 0x01)
                {
                    dictSize = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
                    pos += 3;
                }

                int uncompSize = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2] + 1;
                pos += 3;

                int compSize = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2] + 1;
                pos += 3;

                if (compSize > data.Length - pos) compSize = data.Length - pos;

                var lzmaProps = new byte[5];
                if (pos + 5 <= data.Length)
                {
                    Array.Copy(data, pos, lzmaProps, 0, 5);
                    var decoder = new LzmaDecoder(data, pos + 5, compSize - 5, lzmaProps);
                    decoder.Decompress(output, uncompSize);
                    pos += compSize;
                }
                continue;
            }

            if (ctrl >= 0x80)
            {
                int uncompSize = ((ctrl & 0x1F) << 16) | (data[pos] << 8) | data[pos + 1] + 1;
                pos += 2;

                int compSize = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2] + 1;
                pos += 3;

                bool propsReset = ctrl >= 0xE0;
                bool stateReset = ctrl >= 0xC0;
                int propsSize = propsReset ? 5 : 0;
                int headerSkip = propsSize;

                var lzmaProps = new byte[5];
                if (propsReset && pos + 5 <= data.Length)
                {
                    Array.Copy(data, pos, lzmaProps, 0, 5);
                }
                else if (!propsReset)
                {
                    lzmaProps = new byte[] { 0x5D, 0x00, 0x00, 0x00, 0x01 };
                }

                if (pos + headerSkip + compSize > data.Length) compSize = data.Length - pos - headerSkip;
                if (compSize < 0) compSize = 0;

                var decoder = new LzmaDecoder(data, pos + headerSkip, compSize, lzmaProps);
                decoder.Decompress(output, uncompSize);
                pos += headerSkip + compSize;
                continue;
            }
        }

        return output.ToArray();
    }

    private class LzmaDecoder
    {
        private readonly byte[] _data;
        private int _pos;
        private readonly int _end;
        private uint _range;
        private uint _code;
        private int _lc, _lp, _pb;
        private int _dictSize;
        private byte _prevByte;
        private int _state;
        private int _rep0, _rep1, _rep2, _rep3;
        private readonly byte[] _dict;
        private int _dictPos;

        private const int kNumBitModelTotalBits = 11;
        private const uint kBitModelTotal = 1u << kNumBitModelTotalBits;
        private const int kNumMoveBits = 5;

        private ushort[] _isMatch = new ushort[12 * 4];
        private ushort[] _isRep = new ushort[12];
        private ushort[] _isRepG0 = new ushort[12];
        private ushort[] _isRepG1 = new ushort[12];
        private ushort[] _isRepG2 = new ushort[12];
        private ushort[] _isRep0Long = new ushort[12 * 4];
        private ushort[] _posSlotDecoder = new ushort[4 * 64];
        private ushort[] _posDecoders = new ushort[4 + 4 + 4 + 4 + 4 + 4 * 4 + 4 * 4 + 4 * 4 + 4 * 4];
        private ushort[] _distAlignDecoders = new ushort[4 + 4 + 4 + 4];
        private ushort[] _litProbs;
        private ushort[] _lenDecoders = new ushort[16];
        private ushort[] _repLenDecoders = new ushort[16];

        private const int kNumLenToPosStates = 4;
        private const int kNumAlignBits = 4;
        private const int kAlignTableSize = 1 << kNumAlignBits;

        public LzmaDecoder(byte[] data, int pos, int size, byte[] props)
        {
            _data = data;
            _pos = pos;
            _end = Math.Min(pos + size, data.Length);

            if (props.Length < 5) props = new byte[] { 0x5D, 0x00, 0x00, 0x00, 0x01 };

            _lc = props[0] % 9;
            _lp = (props[0] / 9) % 5;
            _pb = props[0] / 45;

            _dictSize = props[1] | (props[2] << 8) | (props[3] << 16) | (props[4] << 24);
            if (_dictSize < 4096) _dictSize = 4096;

            _dict = new byte[_dictSize];

            int litCtx = _lc * _lp * 0x300;
            _litProbs = new ushort[litCtx == 0 ? 0x300 : litCtx];

            Init();
        }

        private void Init()
        {
            uint initVal = kBitModelTotal / 2;
            Array.Fill(_isMatch, (ushort)initVal);
            Array.Fill(_isRep, (ushort)initVal);
            Array.Fill(_isRepG0, (ushort)initVal);
            Array.Fill(_isRepG1, (ushort)initVal);
            Array.Fill(_isRepG2, (ushort)initVal);
            Array.Fill(_isRep0Long, (ushort)initVal);
            Array.Fill(_posSlotDecoder, (ushort)initVal);
            Array.Fill(_posDecoders, (ushort)initVal);
            Array.Fill(_distAlignDecoders, (ushort)initVal);
            Array.Fill(_lenDecoders, (ushort)initVal);
            Array.Fill(_repLenDecoders, (ushort)initVal);
            Array.Fill(_litProbs, (ushort)initVal);

            _range = 0xFFFFFFFF;
            _code = 0;
            for (int i = 0; i < 5 && _pos < _end; i++)
                _code = (_code << 8) | _data[_pos++];
            _state = 0;
            _rep0 = _rep1 = _rep2 = _rep3 = 0;
            _prevByte = 0;
            _dictPos = 0;
        }

        public void Decompress(Stream output, int uncompSize)
        {
            int remaining = uncompSize;

            while (remaining > 0 && _pos < _end)
            {
                int posState = _dictPos & ((1 << _pb) - 1);
                int stateIdx = (_state << 2) + posState;

                if (DecodeBit(ref _isMatch[stateIdx]) == 0)
                {
                    DecodeLiteral();
                    remaining--;
                    continue;
                }

                int len;
                if (DecodeBit(ref _isRep[_state]) != 0)
                {
                    if (DecodeBit(ref _isRepG0[_state]) == 0)
                    {
                        if (DecodeBit(ref _isRep0Long[stateIdx]) == 0)
                        {
                            _state = _state < 7 ? 9 : 11;
                            FlushByte(output, GetByte(_rep0));
                            remaining--;
                            continue;
                        }
                    }
                    else
                    {
                        int dist;
                        if (DecodeBit(ref _isRepG1[_state]) == 0)
                            dist = _rep1;
                        else
                        {
                            if (DecodeBit(ref _isRepG2[_state]) == 0)
                                dist = _rep2;
                            else
                                dist = _rep3;
                            _rep3 = _rep2;
                        }
                        _rep2 = _rep1;
                        _rep1 = _rep0;
                        _rep0 = dist;
                    }
                    len = DecodeLen(_repLenDecoders, posState);
                    _state = _state < 7 ? 8 : 11;
                }
                else
                {
                    _rep3 = _rep2;
                    _rep2 = _rep1;
                    _rep1 = _rep0;
                    len = DecodeLen(_lenDecoders, posState);
                    _state = _state < 7 ? 7 : 10;
                    _rep0 = DecodeDistance();
                    if (_rep0 == -1) return;
                }

                int copyLen = len + 2;
                while (copyLen > 0 && remaining > 0)
                {
                    FlushByte(output, GetByte(_rep0));
                    copyLen--;
                    remaining--;
                }
            }

            if (remaining > 0 && _dictPos > 0)
            {
                int copy = Math.Min(remaining, _dictPos);
                output.Write(_dict, 0, copy);
            }
        }

        private void FlushByte(Stream output, byte b)
        {
            _prevByte = b;
            if (_dictPos >= _dictSize) _dictPos = 0;
            _dict[_dictPos++] = b;
            output.WriteByte(b);
        }

        private byte GetByte(int dist)
        {
            int idx = _dictPos - dist - 1;
            if (idx < 0) idx += _dictSize;
            return _dict[idx % _dictSize];
        }

        private void DecodeLiteral()
        {
            int litState = ((int)_prevByte >> (8 - _lc)) & ((1 << _lc) - 1);
            int numLitBits = _lp + _lp + _lp;
            int context = litState * 0x300 + numLitBits;

            int sym = 1;
            int matchByte = _state < 7 ? 0 : GetByte(_rep0);

            if (_state >= 7)
            {
                byte matchBit;
                do
                {
                    matchByte <<= 1;
                    matchBit = (byte)((matchByte & 0x100) >> 8);
                    int bit = DecodeBit(ref _litProbs[0x100 + context + (matchBit << 8) + sym]);
                    sym = (sym << 1) | bit;
                } while (sym < 0x100);
            }
            else
            {
                do
                {
                    int bit = DecodeBit(ref _litProbs[context + sym]);
                    sym = (sym << 1) | bit;
                } while (sym < 0x100);
            }

            FlushByte(Stream.Null, (byte)sym);
            if (_state < 4) _state = 0;
            else if (_state < 10) _state -= 3;
            else _state -= 6;
        }

        private int DecodeLen(ushort[] probs, int posState)
        {
            if (DecodeBit(ref probs[0]) == 0) return DecodeBit(ref probs[1]) == 0 ? 0 : 1;

            int len = 2;
            if (DecodeBit(ref probs[2]) == 0)
            {
                len += DecodeBit(ref probs[3]) == 0 ? 0 : 1;
            }
            else
            {
                len += 2;
                int choice = DecodeBit(ref probs[4]);
                len += DecodeBit(ref probs[5 + (choice << 2)]) << 2;
                len += DecodeBit(ref probs[6 + (choice << 2)]) << 1;
                len += DecodeBit(ref probs[7 + (choice << 2)]);
            }

            if (len >= 10)
            {
                len += DecodeBit(ref probs[8]) == 0 ? 0 : 8;
                if (len >= 18)
                {
                    int high = 0;
                    for (int i = 0; i < 4; i++)
                        high = (high << 1) | DecodeBit(ref probs[9 + i]);
                    len = 18 + high;
                }
            }

            return len;
        }

        private int DecodeDistance()
        {
            int lenState = _dictPos < 4 ? _dictPos : 3;
            int posSlot = 0;
            for (int i = 0; i < 6; i++)
                posSlot = (posSlot << 1) | (int)DecodeBit(ref _posSlotDecoder[(lenState << 6) + (posSlot & 0x3F)]);

            if (posSlot < 4) return posSlot;

            int numDirectBits = (posSlot >> 1) - 1;
            int dist = (2 | (posSlot & 1)) << numDirectBits;

            if (posSlot < 14)
            {
                int idx = ((posSlot - 4) << 1) + (lenState << 6) - 4 - 2;
                dist |= (int)DecodeReverseBit(ref _posDecoders, idx, numDirectBits);
            }
            else
            {
                dist |= ((int)DecodeDirectBits(numDirectBits - kNumAlignBits) << kNumAlignBits);
                dist |= (int)DecodeReverseBit(ref _distAlignDecoders, 0, kNumAlignBits);
            }

            return dist;
        }

        private uint DecodeDirectBits(int count)
        {
            uint result = 0;
            for (int i = 0; i < count; i++)
            {
                _range >>= 1;
                _code -= _range;
                uint t = 0x80000000u - (uint)_code;
                if ((int)t >= 0)
                {
                    _code += _range;
                }
                else
                {
                    result = (result << 1) | 1;
                }
                Normalize();
            }
            return result;
        }

        private uint DecodeReverseBit(ref ushort[] probs, int startIdx, int count)
        {
            uint result = 0;
            int idx = startIdx;
            for (int i = 0; i < count; i++)
            {
                int bit = DecodeBit(ref probs[idx]);
                result |= (uint)bit << i;
                idx = startIdx + (int)(result & ((1u << (i + (count <= 4 ? 0 : 6))) - 1));
                if (i >= 6) idx += (count - 7) * 4;
            }
            return result;
        }

        private int DecodeBit(ref ushort prob)
        {
            uint bound = (_range >> kNumBitModelTotalBits) * prob;
            if (_code < bound)
            {
                _range = bound;
                prob += (ushort)((kBitModelTotal - prob) >> kNumMoveBits);
                Normalize();
                return 0;
            }
            _range -= bound;
            _code -= bound;
            prob -= (ushort)(prob >> kNumMoveBits);
            Normalize();
            return 1;
        }

        private void Normalize()
        {
            if (_range < 0x1000000)
            {
                _range <<= 8;
                if (_pos < _end)
                    _code = (_code << 8) | _data[_pos++];
                else
                    _code <<= 8;
            }
        }
    }
}
