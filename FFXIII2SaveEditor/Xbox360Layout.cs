using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FFXIII2SaveEditor;

// Converts a decrypted Xbox 360 APP.DAT to the PS3 layout the editor works on, and back.
//
// Layout differences (measured on a real decrypted Xbox 360 save):
//   * The Xbox 360 file starts with a 0x110-byte header; game data (db_partyman ...) follows.
//   * 0x20 bytes are missing somewhere between Gil (0x2316) and the character table (0x2B000+).
//     Gil reads correctly unshifted; Serah/Noel/Mog read correctly at PS3 offset - 0x20.
//     The exact location of the gap is unknown, so every PS3 offset in LockedStart..LockedEnd
//     (chocobo RP, poker/Chronobind stats, Fragment Skills) is unverified and locked, except the
//     fields listed in VerifiedInLockedRange.
//     Casino coins (0x10CBA) were verified unshifted on a real Xbox 360 save holding 100 coins.
//   * Each inventory bag is 4 + capacity * 24 bytes instead of 4 + capacity * 32 (18-byte
//     records followed by zero padding). The 4-byte bag header holds a different value than on
//     PS3, so it is replaced by the logical count on load and restored unchanged on save.
//   * 0x4A0 further bytes are missing between the last bag and the accessory manager.
//   * There is no PS3-style checksum at the end of the file.
// Every inserted byte is zero padding; on save the padding must still be zero and is removed,
// so an unedited round trip reproduces the original file byte for byte.
public sealed class Xbox360Layout
{
    public const int HeaderSize = 0x110;
    public const int CharacterGapAt = 0x22000;     // Xbox 360 data offset (inside an all-zero area)
    public const int CharacterGapSize = 0x20;
    public const int BagsStartX = 0x4A244;          // Xbox 360 data offset of the Consumables bag
    public const int AccessoryManagerX = 0x59430;   // Xbox 360 data offset of the accessory manager
    public const int ManagerGapSize = 0x4A0;
    public const int X360SlotSize = 24;
    public const int Ps3SlotSize = 32;
    public const int RecordSize = 18;
    public const int ChecksumTrailer = 8;

    // PS3-layout range whose Xbox 360 position is not verified. Edits here are reverted.
    public const int LockedStart = 0x2400;
    public const int LockedEnd = CharacterGapAt;

    // Fields inside the locked range whose Xbox 360 position has been confirmed on a real save.
    private static readonly (int Offset, int Length)[] VerifiedInLockedRange =
    {
        (SaveCore.CasinoCoinsOffset, 4), // BE32, confirmed with 100 coins in game
    };

    public byte[] Header { get; private init; } = Array.Empty<byte>();
    public uint[] OriginalBagHeaders { get; private init; } = Array.Empty<uint>();
    public int DataLength { get; private init; }
    // True when the file on disk was encrypted; saving then encrypts again (Xbox360Crypto).
    public bool Encrypted { get; private init; }

    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("db_partyman");

    public static bool LooksLikeXbox360(byte[] file)
    {
        if (file.Length < HeaderSize + AccessoryManagerX + 0x100) return false;
        if (!file.AsSpan(HeaderSize, Marker.Length).SequenceEqual(Marker)) return false;
        // The accessory manager must start where the Xbox 360 layout puts it (an "acc_" ID or an empty record).
        var acc = file.AsSpan(HeaderSize + AccessoryManagerX, 4);
        return acc.SequenceEqual("acc_"u8) || file.AsSpan(HeaderSize + AccessoryManagerX, 18).IndexOfAnyExcept((byte)0) < 0;
    }

    private static int BagBlockLengthX() => SaveCore.InventoryBags.Sum(b => 4 + b.Capacity * X360SlotSize);
    private static int BagBlockLengthPs3() => SaveCore.InventoryBags.Sum(b => 4 + b.Capacity * Ps3SlotSize);

    // file: decrypted Xbox 360 APP.DAT (header + data). encrypted: whether the copy on disk was encrypted.
    public static (byte[] Ps3, Xbox360Layout Layout) ToPs3(byte[] file, bool encrypted = false)
    {
        if (!LooksLikeXbox360(file)) throw new InvalidDataException("This is not a recognised decrypted Xbox 360 APP.DAT.");
        byte[] x = file.AsSpan(HeaderSize).ToArray();
        int bagsEndX = BagsStartX + BagBlockLengthX();
        int bagsStartP = BagsStartX + CharacterGapSize;
        int bagsEndP = bagsStartP + BagBlockLengthPs3();
        if (bagsEndP + (AccessoryManagerX - bagsEndX) + ManagerGapSize != SaveCore.AccessoryManagerBase)
            throw new InvalidDataException("Internal Xbox 360 layout table does not match the PS3 layout.");

        var p = new byte[x.Length + CharacterGapSize + (BagBlockLengthPs3() - BagBlockLengthX()) + ManagerGapSize + ChecksumTrailer];
        // 1) data before the 0x20 gap, 2) data up to the bags
        x.AsSpan(0, CharacterGapAt).CopyTo(p);
        x.AsSpan(CharacterGapAt, BagsStartX - CharacterGapAt).CopyTo(p.AsSpan(CharacterGapAt + CharacterGapSize));
        // 3) bags
        var headers = new uint[SaveCore.InventoryBags.Length];
        int ox = BagsStartX;
        for (int i = 0; i < SaveCore.InventoryBags.Length; i++)
        {
            var bag = SaveCore.InventoryBags[i];
            int op = bag.Base;
            headers[i] = BinaryPrimitives.ReadUInt32BigEndian(x.AsSpan(ox, 4));
            int records = bag.Capacity * RecordSize;
            x.AsSpan(ox + 4, records).CopyTo(p.AsSpan(op + 4));
            x.AsSpan(ox + 4 + records, bag.Capacity * (X360SlotSize - RecordSize)).CopyTo(p.AsSpan(op + 4 + records));
            BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(op, 4), (uint)LogicalCount(x, ox + 4, bag.Capacity));
            ox += 4 + bag.Capacity * X360SlotSize;
        }
        // 4) between bags and accessory manager, 5) the 0x4A0 gap, 6) everything after
        x.AsSpan(bagsEndX, AccessoryManagerX - bagsEndX).CopyTo(p.AsSpan(bagsEndP));
        x.AsSpan(AccessoryManagerX).CopyTo(p.AsSpan(SaveCore.AccessoryManagerBase));

        var layout = new Xbox360Layout { Header = file.AsSpan(0, HeaderSize).ToArray(), OriginalBagHeaders = headers, DataLength = x.Length, Encrypted = encrypted };
        p = SaveCore.RepairChecksum(p);
        if (!layout.FromPs3(p).AsSpan().SequenceEqual(file))
            throw new InvalidDataException("Xbox 360 layout conversion did not round-trip exactly; refusing to open this file.");
        return (p, layout);
    }

    public byte[] FromPs3(byte[] p)
    {
        int bagsEndX = BagsStartX + BagBlockLengthX();
        int bagsStartP = BagsStartX + CharacterGapSize;
        int bagsEndP = bagsStartP + BagBlockLengthPs3();
        int expected = DataLength + CharacterGapSize + (BagBlockLengthPs3() - BagBlockLengthX()) + ManagerGapSize + ChecksumTrailer;
        if (p.Length != expected) throw new InvalidDataException("Edited data has an unexpected size for an Xbox 360 save.");

        RequireZero(p, CharacterGapAt, CharacterGapSize, "character gap");
        RequireZero(p, SaveCore.AccessoryManagerBase - ManagerGapSize, ManagerGapSize, "manager gap");

        var x = new byte[DataLength];
        p.AsSpan(0, CharacterGapAt).CopyTo(x);
        p.AsSpan(CharacterGapAt + CharacterGapSize, BagsStartX - CharacterGapAt).CopyTo(x.AsSpan(CharacterGapAt));
        int ox = BagsStartX;
        for (int i = 0; i < SaveCore.InventoryBags.Length; i++)
        {
            var bag = SaveCore.InventoryBags[i];
            int op = bag.Base;
            int records = bag.Capacity * RecordSize;
            int padX = bag.Capacity * (X360SlotSize - RecordSize);
            int padP = bag.Capacity * (Ps3SlotSize - RecordSize);
            RequireZero(p, op + 4 + records + padX, padP - padX, bag.Name + " padding");
            BinaryPrimitives.WriteUInt32BigEndian(x.AsSpan(ox, 4), OriginalBagHeaders[i]);
            p.AsSpan(op + 4, records + padX).CopyTo(x.AsSpan(ox + 4));
            ox += 4 + bag.Capacity * X360SlotSize;
        }
        p.AsSpan(bagsEndP, AccessoryManagerX - bagsEndX).CopyTo(x.AsSpan(bagsEndX));
        p.AsSpan(SaveCore.AccessoryManagerBase, DataLength - AccessoryManagerX).CopyTo(x.AsSpan(AccessoryManagerX));
        return Header.Concat(x).ToArray();
    }

    // The 0x110-byte header holds the slot summary the game shows in its load menu, e.g.
    // "Godzin gry: 005:23:46\nFragmentów: 011/160". The label is localised, so only "NNN/160" is matched.
    public static int ReadHeaderFragmentCount(byte[] file)
    {
        if (file.Length < HeaderSize) return -1;
        string text = Encoding.Latin1.GetString(file, 0, HeaderSize);
        var m = System.Text.RegularExpressions.Regex.Match(text, @"(\d{1,3})/" + SaveCore.FragmentCount + @"(?!\d)");
        return m.Success && int.TryParse(m.Groups[1].Value, out int n) && n <= SaveCore.FragmentCount ? n : -1;
    }

    // Bytes to write to disk: decrypted Xbox 360 file, encrypted again if the original was encrypted.
    public byte[] ToFile(byte[] ps3) => Encrypted ? Xbox360Crypto.EncryptFile(FromPs3(ps3)) : FromPs3(ps3);

    // Revert any change inside the unverified range. Returns true if something was reverted.
    public static bool RevertLockedRange(byte[] edited, byte[] baseline)
    {
        if (edited.Length != baseline.Length) return false;
        bool reverted = false;
        int start = LockedStart;
        foreach (var (offset, length) in VerifiedInLockedRange.OrderBy(v => v.Offset).Append((LockedEnd, 0)))
        {
            reverted |= RevertSpan(edited, baseline, start, offset - start);
            start = offset + length;
        }
        return reverted;
    }

    private static bool RevertSpan(byte[] edited, byte[] baseline, int offset, int length)
    {
        if (length <= 0) return false;
        var span = edited.AsSpan(offset, length);
        var original = baseline.AsSpan(offset, length);
        if (span.SequenceEqual(original)) return false;
        original.CopyTo(span);
        return true;
    }

    private static int LogicalCount(byte[] x, int recordsStart, int capacity)
    {
        int count = capacity;
        while (count > 0 && x.AsSpan(recordsStart + (count - 1) * RecordSize, RecordSize).IndexOfAnyExcept((byte)0) < 0) count--;
        return count;
    }

    private static void RequireZero(byte[] p, int offset, int length, string what)
    {
        if (length > 0 && p.AsSpan(offset, length).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException($"An edit touched Xbox 360 {what} bytes that do not exist in the Xbox 360 file; refusing to save.");
    }
}
