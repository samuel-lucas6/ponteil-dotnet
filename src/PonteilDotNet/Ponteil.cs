namespace PonteilDotNet;

public static class Ponteil
{
    public const int TagSize = 32;
    public const int HashSize = 32;
    public const int KeySize = 32;
    public const int BlockSize = 32;

    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default)
    {
        if (tag.Length == 0) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be greater than 0 bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (PonteilX86.IsSupported()) {
            PonteilX86.ComputeTag(tag, message, key, context);
        }
        else if (PonteilArm.IsSupported()) {
            PonteilArm.ComputeTag(tag, message, key, context);
        }
        else {
            throw new PlatformNotSupportedException();
        }
    }

    public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context = default)
    {
        if (hash.Length == 0) { throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"{nameof(hash)} must be greater than 0 bytes long."); }

        if (PonteilX86.IsSupported()) {
            PonteilX86.ComputeHash(hash, message, context);
        }
        else if (PonteilArm.IsSupported()) {
            PonteilArm.ComputeHash(hash, message, context);
        }
        else {
            throw new PlatformNotSupportedException();
        }
    }
}
