using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PonteilDotNet;

internal static class PonteilX86
{
    private static Vector128<byte> _s0, _s1, _s2, _s3, _s4, _s5, _s6, _s7;
    private static ulong _ctxSegments;
    private static ulong _msgSegments;
    private static bool _keyed;

    internal static bool IsSupported() => Aes.IsSupported;

    internal static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default)
    {
        Initialize(key);
        if (context.Length != 0) {
            PushContext(context);
        }
        Push(message);
        Finalize(tag);
    }

    internal static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context = default)
    {
        Initialize();
        if (context.Length != 0) {
            PushContext(context);
        }
        Push(message);
        Finalize(hash);
    }

    private static void Initialize(ReadOnlySpan<byte> key = default)
    {
        _ctxSegments = 0;
        _msgSegments = 0;

        if (key.Length != 0) {
            Init(key);
            _keyed = true;
            return;
        }

        Span<byte> emptyKey = stackalloc byte[Ponteil.KeySize];
        emptyKey.Clear();
        Init(emptyKey);
        _keyed = false;
    }

    private static void Init(ReadOnlySpan<byte> key)
    {
        Vector128<byte> c0 = Vector128.Create(0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62);
        Vector128<byte> c1 = Vector128.Create(0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd);
        Vector128<byte> zero = Vector128<byte>.Zero;
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);

        _s0 = zero;
        _s1 = k1;
        _s2 = k0 ^ c1;
        _s3 = k0 ^ c0;
        _s4 = zero;
        _s5 = k0;
        _s6 = k1 ^ c0;
        _s7 = k1 ^ c1;

        for (int i = 0; i < 12; i++) {
            Update(c0, c1);
        }
    }

    private static void Update(Vector128<byte> m0, Vector128<byte> m1)
    {
        Vector128<byte> s0 = Aes.Encrypt(_s7, _s0 ^ m0);
        Vector128<byte> s1 = Aes.Encrypt(_s0, _s1);
        Vector128<byte> s2 = Aes.Encrypt(_s1, _s2);
        Vector128<byte> s3 = Aes.Encrypt(_s2, _s3);
        Vector128<byte> s4 = Aes.Encrypt(_s3, _s4 ^ m1);
        Vector128<byte> s5 = Aes.Encrypt(_s4, _s5);
        Vector128<byte> s6 = Aes.Encrypt(_s5, _s6);
        Vector128<byte> s7 = Aes.Encrypt(_s6, _s7);

        _s0 = s0;
        _s1 = s1;
        _s2 = s2;
        _s3 = s3;
        _s4 = s4;
        _s5 = s5;
        _s6 = s6;
        _s7 = s7;
    }

    private static void PushContext(ReadOnlySpan<byte> context)
    {
        Absorb(context, 0x80);
        _ctxSegments += 1;
    }

    private static void Push(ReadOnlySpan<byte> message)
    {
        Absorb(message, 0x00);
        _msgSegments += 1;
    }

    private static void Absorb(ReadOnlySpan<byte> x, byte up)
    {
        int i = 0;
        if (_keyed) {
            while (i + 32 <= x.Length) {
                AbsorbBlock(x.Slice(i, 32));
                i += 32;
            }
            if (x.Length % 32 != 0) {
                Span<byte> padding = stackalloc byte[Ponteil.BlockSize];
                padding.Clear();
                x[i..].CopyTo(padding);
                AbsorbBlock(padding);
            }
        }
        else {
            Span<byte> padding = stackalloc byte[Ponteil.BlockSize];
            padding.Clear();
            while (i + 16 <= x.Length) {
                x.Slice(i, 8).CopyTo(padding[..8]);
                x.Slice(i + 8, 8).CopyTo(padding[16..24]);
                AbsorbBlock(padding);
                i += 16;
            }
            int remaining = x.Length % 16;
            if (remaining != 0) {
                padding.Clear();
                int length = Math.Min(remaining, 8);
                x.Slice(i, length).CopyTo(padding);
                if (remaining > 8) {
                    length = remaining - 8;
                    x.Slice(i + 8, length).CopyTo(padding.Slice(16, length));
                }
                AbsorbBlock(padding);
            }
        }

        Span<byte> messageLength = stackalloc byte[Ponteil.BlockSize];
        messageLength.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(messageLength[..8], (ulong)x.Length * 8);
        messageLength[31] ^= up;
        AbsorbBlock(messageLength);
    }

    private static void AbsorbBlock(ReadOnlySpan<byte> xi)
    {
        Vector128<byte> t0 = Vector128.Create(xi[..16]);
        Vector128<byte> t1 = Vector128.Create(xi[16..]);
        Update(t0, t1);
    }

    private static void Finalize(Span<byte> output)
    {
        var segments = new byte[16]; Span<byte> s = segments;
        BinaryPrimitives.WriteUInt64LittleEndian(s[..8], _ctxSegments * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(s[8..], _msgSegments * 8);

        Vector128<byte> t = _s2 ^ Vector128.Create(segments);
        int i;
        for (i = 0; i < 11; i++) {
            Update(t, t);
        }

        i = 0;
        while (i + 32 <= output.Length) {
            Update(t, t);
            Vector128<byte> out1 = _s1 ^ _s6 ^ (_s2 & _s3);
            Vector128<byte> out2 = _s2 ^ _s5 ^ (_s6 & _s7);
            out1.CopyTo(output.Slice(i, 16));
            out2.CopyTo(output.Slice(i + 16, 16));
            i += 32;
        }
        if (output.Length % 32 != 0) {
            Update(t, t);
            Span<byte> padding = stackalloc byte[Ponteil.BlockSize];
            Vector128<byte> out1 = _s1 ^ _s6 ^ (_s2 & _s3);
            Vector128<byte> out2 = _s2 ^ _s5 ^ (_s6 & _s7);
            out1.CopyTo(padding[..16]);
            out2.CopyTo(padding[16..]);
            padding[..(output.Length % 32)].CopyTo(output[i..]);
        }
    }
}
