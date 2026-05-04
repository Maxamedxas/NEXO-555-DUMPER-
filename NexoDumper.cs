using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SaaxibUniversalV121
{
    #region 🎯 FIXED ARM64 ADR EXTRACTOR
    public class CrossArchResolver
    {
        private readonly byte[] _binary;
        public Dictionary<ulong, string> Pointers { get; } = new Dictionary<ulong, string>();
        public Arch DetectedArch { get; private set; }

        public CrossArchResolver(byte[] binary)
        {
            _binary = binary;
            DetectArch();
            ResolvePointers();
        }

        private void DetectArch()
        {
            if (_binary.Length > 18)
            {
                var eMachine = BinaryPrimitives.ReadUInt16BigEndian(_binary.AsSpan(18, 2));
                DetectedArch = eMachine switch
                {
                    183 => Arch.AARCH64,  // 0xB7
                    40 => Arch.ARM,       // 0x28
                    62 => Arch.X86_64,    // 0x3E
                    _ => Arch.X86_64
                };
            }
        }

        private void ResolvePointers()
        {
            var patterns = DetectedArch switch
            {
                Arch.AARCH64 => Arm64Patterns(),
                Arch.ARM => ArmPatterns(),
                _ => X64Patterns()
            };

            foreach (var sig in patterns)
            {
                ScanPattern(sig);
            }
        }

        private static List<(byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract)> Arm64Patterns()
        {
            return new List<(byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract)>
            {
                (new byte[] { 0x10, 0x00, 0x00, 0x00 }, ExtractAdrPcrel),
                (new byte[] { 0x10, 0x00, 0x00, 0x90 }, ExtractAdrp),
                (new byte[] { 0x58, 0x00, 0x00, 0x00 }, ExtractLdrLiteral),
                (new byte[] { 0x52, 0x00, 0x00, 0x00 }, ExtractMovz)
            };
        }

        private static ulong ExtractAdrPcrel(ReadOnlySpan<byte> span, int offset)
        {
            var instr = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, 4));
            var imm21 = (instr >> 5) & 0x7FFFF;
            var isNegative = (instr & (1 << 30)) != 0;
            var pc = (ulong)(offset + 4);
            var target = pc + (ulong)((long)imm21 << 12);
            if (isNegative) target -= 0x200000;
            return target;
        }

        private static ulong ExtractAdrp(ReadOnlySpan<byte> span, int offset)
        {
            var instr = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, 4));
            var imm21 = (instr >> 5) & 0x7FFFF;
            var pc = (ulong)(offset + 4);
            var page = pc & ~0xFFFUL;
            return page + ((ulong)imm21 << 12);
        }

        private static ulong ExtractLdrLiteral(ReadOnlySpan<byte> span, int offset)
        {
            var instr = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, 4));
            var imm19 = (instr >> 5) & 0x7FFFF;
            var pc = (ulong)(offset + 4);
            return pc + (ulong)((long)imm19 << 2);
        }

        private static ulong ExtractMovz(ReadOnlySpan<byte> span, int offset)
        {
            var instr = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, 4));
            var imm16 = (instr >> 5) & 0xFFFF;
            var shift = (int)((instr >> 21) & 3) * 16;
            return (ulong)imm16 << shift;
        }

        private static List<(byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract)> ArmPatterns() => new();
        private static List<(byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract)> X64Patterns()
        {
            return new List<(byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract)>
            {
                (new byte[] { 0x48, 0xB8 }, (s, o) => BinaryPrimitives.ReadUInt64LittleEndian(s.Slice(o + 2, 8)))
            };
        }

        private void ScanPattern((byte[] pattern, Func<ReadOnlySpan<byte>, int, ulong> extract) sig)
        {
            for (int i = 0; i < _binary.Length - sig.pattern.Length; i++)
            {
                if (_binary.AsSpan(i, sig.pattern.Length).SequenceEqual(sig.pattern))
                {
                    var ptr = sig.extract(_binary.AsSpan(), i);
                    if (ptr != 0 && ptr < 0x1000000000UL && !Pointers.ContainsKey(ptr))
                    {
                        Pointers[ptr] = $"ARM64_method_{i:X8}";
                    }
                }
            }
        }
    }

    public enum Arch { X86_64, AARCH64, ARM }
    #endregion

    #region 🎯 FIXED XOR BRUTE-FORCE
    public class MetadataDecryptor
    {
        public static byte[] Decrypt(byte[] data)
        {
            for (int key = 0; key < 256; key++)
            {
                var testData = XorData(data, (byte)key);
                if (IsValidMetadata(testData))
                {
                    Console.WriteLine($"✅ Key found: 0x{key:X2}");
                    return testData;
                }
            }
            return data;
        }

        private static bool IsValidMetadata(byte[] data)
        {
            if (data.Length < 0x40) return false;
            var version = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4, 4));
            return version >= 20 && version <= 35;
        }

        private static byte[] XorData(byte[] data, byte key)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) result[i] = (byte)(data[i] ^ key);
            return result;
        }
    }
    #endregion

    public class Il2CppType { public string Name; public uint Token; }

    public class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2) {
                Console.WriteLine("Usage: NexoDumper <libil2cpp.so> <global-metadata.dat>");
                return;
            }
            Console.WriteLine("🔥 Saaxib v12.1 UNIVERSAL (ARM64+XOR FIXED) 🔥");
            
            byte[] binaryRaw = File.ReadAllBytes(args[0]);
            byte[] metadataRaw = MetadataDecryptor.Decrypt(File.ReadAllBytes(args[1]));

            var resolver = new CrossArchResolver(binaryRaw);
            Console.WriteLine($"Arch: {resolver.DetectedArch}");
            Console.WriteLine($"Pointers Found: {resolver.Pointers.Count}");
        }
    }
}
