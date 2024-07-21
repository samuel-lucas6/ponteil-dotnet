namespace PonteilDotNet.Tests;

[TestClass]
public class PonteilTests
{
    // Made myself based on https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-11#appendix-A.3
    public static IEnumerable<object[]> TagTestVectors()
    {
        yield return
        [
            "31af58c44181ba194913c005c5535b143171cdec2228b57285bcdeefe0199272",
            "",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "824bbec1d9487622219e25fda94c7ef2db8d437e31552e1593c8452adfdd0295",
            "",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        ];
        yield return
        [
            "6b81b5ec8e1275d437bc9a978c251db00f408581b07dad4c31bbebf86c4275a5",
            "00000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "7fc07fc7adce107fcd065c95e1b9ae1a45c38c91b24a3a2f91dc7c7e48eb3f31",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "496fd0feeb073de6f94d9962fdaf22c3cd78d5c2309ed73b06426462bee8a249",
            "000102030405060708090a0b0c0d",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "0e73fa6e711df67bf135e37a0d45c7c4fbf2a68dfcf550cea621151925be6314",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        ];
    }

    // Made myself based on https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-11#appendix-A.2
    public static IEnumerable<object[]> HashTestVectors()
    {
        yield return
        [
            "7c4ac47d19605e9b2b4183941f57f82bf698de46b4a3c91a0aa8196a9fa82b47",
            "",
            ""
        ];
        yield return
        [
            "b106111b03497c0f8c6d51c325d5235cc38057b794054a7a39141312fe4f257a",
            "",
            "0001020304050607"
        ];
        yield return
        [
            "870d68deb5b3ec51226aebc1db4020f5e1d14b59132c3d54f0136775a048efd6",
            "00000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "ccdf7ab549250a16599c6007b84a623d229bc6ee90058ec7b34513dc9db52beb",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ""
        ];
        yield return
        [
            "8688ffcbf7d363807986bdad6794b791ce8a260e79bba5232a07021aee38131a",
            "000102030405060708090a0b0c0d",
            ""
        ];
        yield return
        [
            "c613e6c2778dc02096b4ada0d746218852d8566643e61eb83bb9148546837f79",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
    }

    [TestMethod]
    [DynamicData(nameof(TagTestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key, string context)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> c = Convert.FromHexString(context);

        Ponteil.ComputeTag(t, m, k, c);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, Ponteil.KeySize, 0)]
    [DataRow(Ponteil.TagSize, 1, Ponteil.KeySize + 1, 0)]
    [DataRow(Ponteil.TagSize, 1, Ponteil.KeySize - 1, 0)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize, int contextSize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];
        var c = new byte[contextSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ponteil.ComputeTag(t, m, k, c));
    }

    [TestMethod]
    [DynamicData(nameof(HashTestVectors), DynamicDataSourceType.Method)]
    public void ComputeHash_Valid(string hash, string message, string context)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> c = Convert.FromHexString(context);

        Ponteil.ComputeHash(h, m, c);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    // https://github.com/jedisct1/ponteil/blob/master/zig/src/main.zig#L171
    [TestMethod]
    public void OfficialHashTestVector()
    {
        Span<byte> hash = stackalloc byte[Ponteil.HashSize];
        Span<byte> message = new byte[100000 - 1];

        Ponteil.ComputeHash(hash, message);

        Assert.AreEqual("60ed63cf13fb49596a567a0b3538d16e6fa22a746531905fb93ed184783b5432", Convert.ToHexString(hash).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, 0)]
    public void ComputeHash_Invalid(int hashSize, int messageSize, int contextSize)
    {
        var h = new byte[hashSize];
        var m = new byte[messageSize];
        var c = new byte[contextSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ponteil.ComputeHash(h, m, c));
    }
}
