using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;

namespace FFXIII2SaveEditor;

// Xbox 360 FFXIII-2 APP.DAT cipher (port of ff13_2_savecrypt.py; output verified byte-for-byte
// against that script). The game's routines: key schedule white.exe 0x8286C950, encrypt
// 0x8286CB58 / 0x8286CCC8, decrypt 0x8286D000 / 0x8286D170.
// File layout: 0x110-byte plain header, then the encrypted data followed by an encrypted 8-byte
// trailer (little-endian data length, little-endian checksum = sum of bytes 0 and 4 of every 8-byte plain block).
public static class Xbox360Crypto
{
    public const int HeaderSize = 0x110;
    // APP.DAT key. It is not a secret constant chosen by the game: it is a hash of the game data
    // file frg_cmn_acfa002, which the game computes at run time (the result sits in guest memory at
    // 0x82E6A298 and is passed to the key schedule at white.exe 0x8286C950). The 8 bytes below are
    // that hash, hard-coded so the editor does not need the game files. Q*.DAT / Q*.DAH files use a
    // different key and are not handled.
    private static readonly byte[] DefaultKey = Convert.FromHexString("6920C2168106440F");
    private static readonly byte[] Marker = System.Text.Encoding.ASCII.GetBytes("db_partyman");

    private static uint RotL32(uint x, int n) => (x << n) | (x >> (32 - n));

    private static ulong[] Schedule(byte[] key8)
    {
        ulong r6 = BinaryPrimitives.ReadUInt64LittleEndian(key8);
        uint lo = (uint)r6, hi = (uint)(r6 >> 32);
        ulong r8 = ((ulong)RotL32(lo, 8) << 32) | RotL32(hi, 16);
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, r8);
        b[0] = (byte)(b[0] + 69);
        for (int i = 1; i < 8; i++)
            b[i] = (byte)((((b[i] + b[i - 1] + 212) ^ (b[i - 1] << 2)) & 255) ^ 69);
        var table = new ulong[32]; // stored as little-endian values of the 8 key bytes
        table[0] = BinaryPrimitives.ReadUInt64LittleEndian(b);
        for (int j = 1; j < 32; j++) table[j] = unchecked(table[j - 1] * 5);
        return table;
    }

    private static ulong CounterKey(int counter)
    {
        unchecked
        {
            ulong c = (uint)counter;
            ulong r6 = (c << 10) | c;
            r6 = ((r6 << 10) & ~0x3FFUL) | c;
            ulong r9 = (r6 << 10) & ~0x3FFUL;
            return (r9 | c) + 0xA1652347UL;
        }
    }

    private static int ByteSum(ulong t)
    {
        int s = 0;
        for (int i = 0; i < 8; i++) s += (int)((t >> (8 * i)) & 0xFF);
        return s;
    }

    private static void EncryptBlock(ulong[] table, int c, ReadOnlySpan<byte> input, Span<byte> output)
    {
        unchecked
        {
            ulong tLe = table[(c >> 3) & 31];
            ulong tBe = BinaryPrimitives.ReverseEndianness(tLe);
            ulong v = BinaryPrimitives.ReadUInt64BigEndian(input);
            v = (v << 32) | (v >> 32);
            ulong x = v ^ tBe ^ BinaryPrimitives.ReverseEndianness(CounterKey(c));
            ulong o = BinaryPrimitives.ReverseEndianness(x) + tLe;
            Span<byte> ob = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(ob, o);
            int step = ByteSum(tLe) + 8 * 0x88;
            byte m = (byte)(((c >> 3) & 255) ^ 69);
            for (int i = 0; i < 8; i++)
            {
                byte y = (byte)((byte)(ob[i] + step) ^ m);
                output[i] = y;
                m = y;
            }
        }
    }

    private static void DecryptBlock(ulong[] table, int c, ReadOnlySpan<byte> input, Span<byte> output)
    {
        unchecked
        {
            ulong tLe = table[(c >> 3) & 31];
            ulong tBe = BinaryPrimitives.ReverseEndianness(tLe);
            int step = ByteSum(tLe) + 8 * 0x88;
            byte m = (byte)(((c >> 3) & 255) ^ 69);
            Span<byte> ob = stackalloc byte[8];
            for (int i = 0; i < 8; i++)
            {
                ob[i] = (byte)((input[i] ^ m) - step);
                m = input[i];
            }
            ulong x = BinaryPrimitives.ReverseEndianness(BinaryPrimitives.ReadUInt64LittleEndian(ob) - tLe);
            ulong v = x ^ tBe ^ BinaryPrimitives.ReverseEndianness(CounterKey(c));
            v = (v << 32) | (v >> 32);
            BinaryPrimitives.WriteUInt64BigEndian(output, v);
        }
    }

    // Encrypted block (data + trailer) -> plain data. Throws if the trailer does not verify.
    public static byte[] DecryptBody(ReadOnlySpan<byte> body, byte[]? key = null)
    {
        if (body.Length < 8 || body.Length % 8 != 0)
            throw new InvalidDataException($"Encrypted Xbox 360 block size {body.Length} is not a multiple of 8.");
        ulong[] table = Schedule(key ?? DefaultKey);
        int n = body.Length - 8;
        var plain = new byte[n];
        uint total = 0;
        for (int i = 0; i < n; i += 8)
        {
            DecryptBlock(table, i, body.Slice(i, 8), plain.AsSpan(i, 8));
            total = unchecked(total + plain[i] + plain[i + 4]);
        }
        Span<byte> trailer = stackalloc byte[8];
        DecryptBlock(table, n, body.Slice(n, 8), trailer);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(trailer);
        uint checksum = BinaryPrimitives.ReadUInt32LittleEndian(trailer[4..]);
        if (length != (uint)n || checksum != total)
            throw new InvalidDataException($"Xbox 360 APP.DAT checksum mismatch (stored {checksum:X8}, computed {total:X8}, length field {length}).");
        return plain;
    }

    public static byte[] EncryptBody(ReadOnlySpan<byte> plain, byte[]? key = null)
    {
        if (plain.Length % 8 != 0)
            throw new InvalidDataException($"Xbox 360 data size {plain.Length} is not a multiple of 8.");
        ulong[] table = Schedule(key ?? DefaultKey);
        var output = new byte[plain.Length + 8];
        uint total = 0;
        for (int i = 0; i < plain.Length; i += 8)
        {
            total = unchecked(total + plain[i] + plain[i + 4]);
            EncryptBlock(table, i, plain.Slice(i, 8), output.AsSpan(i, 8));
        }
        Span<byte> trailer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(trailer, (uint)plain.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(trailer[4..], total);
        EncryptBlock(table, plain.Length, trailer, output.AsSpan(plain.Length, 8));
        return output;
    }

    // Encrypted file (header + block) -> decrypted file (header + data), or null if it is not one.
    public static byte[]? TryDecryptFile(byte[] file)
    {
        if (file.Length < HeaderSize + 16 || (file.Length - HeaderSize) % 8 != 0) return null;
        if (file.AsSpan(HeaderSize, Marker.Length).SequenceEqual(Marker)) return null; // already decrypted
        try
        {
            byte[] plain = DecryptBody(file.AsSpan(HeaderSize));
            if (!plain.AsSpan(0, Marker.Length).SequenceEqual(Marker)) return null;
            return file.AsSpan(0, HeaderSize).ToArray().Concat(plain).ToArray();
        }
        catch (InvalidDataException) { return null; }
    }

    // Decrypted file (header + data) -> encrypted file (header + block with trailer).
    public static byte[] EncryptFile(byte[] decrypted)
        => decrypted.AsSpan(0, HeaderSize).ToArray().Concat(EncryptBody(decrypted.AsSpan(HeaderSize))).ToArray();
}
