// Round-trip check for the 38.00 / 42.40 reflection decryptors.
// Encrypts known-plaintext values with the inverse of what the game stores,
// then asserts the real SDK helpers hand the plaintext back.
#include <Windows.h>
#include "../SDK/Includes.h"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace SDK;

static void Reset()
{
    Crypto = FReflectionCrypto{};
}

// Verbatim copy of FortEncryption::DecryptFieldPtr from the 42.40 dump.
static uint64 RefFieldPtr42(uint64 Raw)
{
    if (!(Raw & 0x1))
        return Raw;

    uint64 P = (((Raw & ~0x1ull) ^ 0x288EDAEE440D7660ull) + 0xCEE68B965D9F5236ull) ^ 0x318C83FD4C27722Eull;
    P = ((uint64)Bswap32((uint32_t)(P >> 32)) << 32) | (P & 0xFFFFFFFEull);

    return (P * 0x5F7E5AB374C71923ull) & ~0x1ull;
}

static void Layout38()
{
    Reset();
    Offsets::FortniteCL = 47722112;
    ApplyEncryptedBuildLayout();
}

static void Layout42()
{
    Reset();
    Offsets::FortniteCL = 59343437;
    ApplyEncryptedBuildLayout();
}

static void Test38()
{
    Layout38();
    assert(Crypto.bKeyScheme && !Crypto.bBswapScheme);

    // UObject::Index : stored ^ 0x753838AB
    {
        alignas(8) uint8_t Obj[0x30] = {};
        const int32 Plain = 0x1234;
        *(int32*)(Obj + Offsets::UObjectIndex) = (uint32)Plain ^ Crypto.ObjectIndexKey;
        assert(ReadObjectIndex(Obj) == Plain);
    }

    // FUObjectItem packed pointer: hi64 at 0x0 masked, low32 at 0x8 ^ key, << 3
    {
        alignas(8) uint8_t Item[0x18] = {};
        const uint64 Ptr = 0x00007FF612345000ull; // 8-byte aligned so >>3 is exact
        const uint64 Packed = Ptr >> Crypto.ItemPtrShift;

        *(uint64*)(Item + Crypto.ItemHiOffset) = Packed & Crypto.ItemHiMask;
        *(uint32*)(Item + Crypto.ItemLoOffset) = (uint32)(Packed & 0xFFFFFFFFull) ^ Crypto.ItemLoKey;

        assert(DecryptObjectItemPtr(Item) == Ptr);
    }

    // FProperty::Offset is plaintext on 38.00
    {
        alignas(8) uint8_t Prop[0x70] = {};
        *(uint32*)(Prop + Offsets::Offset_Internal) = 0x2A8;
        assert(ReadPropertyOffset(Prop) == 0x2A8);
    }

    // FName index is plaintext on 38.00
    {
        FName N(0x1F00);
        assert(N.GetDisplayIndex() == 0x1F00);
    }

    // FField::Next encrypted form: stored = (plain ^ key) | 1
    {
        alignas(8) uint8_t Holder[0x20] = {};
        const uint64 PlainPtr = 0x00007FF612345000ull;
        *(uint64*)Holder = (PlainPtr ^ Crypto.FieldPtrKey) | 1ull;
        assert((uint64)ReadFieldPtr(Holder, 0) == PlainPtr);
    }
}

static void Test42()
{
    Layout42();
    assert(Crypto.bBswapScheme && !Crypto.bKeyScheme);

    // UObject::Index : bswap32(stored) ^ 0xDD1A7CBF
    {
        alignas(8) uint8_t Obj[0x30] = {};
        const int32 Plain = 0x1234;
        *(uint32*)(Obj + Offsets::UObjectIndex) = Bswap32((uint32)Plain ^ Crypto.ObjectIndexKey);
        assert(ReadObjectIndex(Obj) == Plain);
    }

    // FProperty::Offset : bswap32(stored) ^ 0x5E5D3CD4
    {
        alignas(8) uint8_t Prop[0x70] = {};
        *(uint32*)(Prop + Offsets::Offset_Internal) = Bswap32(0x2A8u ^ Crypto.PropertyOffsetKey);
        assert(ReadPropertyOffset(Prop) == 0x2A8);
    }

    // PropertyFlags : bswap64(stored) ^ 0x6B3F5F54
    {
        alignas(8) uint8_t Prop[0x70] = {};
        const uint64 Flags = 0x0000000000000200ull;
        *(uint64*)(Prop + Offsets::PropertyFlags) = Bswap64(Flags ^ Crypto.PropertyFlagsKey);
        assert(ReadPropertyFlags(Prop) == Flags);
    }

    // ElementSize / StructSize are keyed the same way
    {
        alignas(8) uint8_t Prop[0x70] = {};
        *(uint32*)(Prop + Offsets::ElementSize) = Bswap32(0x10u ^ Crypto.ElementSizeKey);
        assert(ReadElementSize(Prop) == 0x10);

        alignas(8) uint8_t Struct[0x100] = {};
        *(uint32*)(Struct + Offsets::PropertiesSize) = Bswap32(0x138u ^ Crypto.StructSizeKey);
        assert(ReadStructSize(Struct) == 0x138);
    }

    // FUObjectItem packed pointer: hi32 at 0x4, low32 at 0x10 bswapped
    {
        alignas(8) uint8_t Item[0x18] = {};
        const uint64 Ptr = 0x00007FF612345000ull;
        const uint64 Packed = Ptr >> Crypto.ItemPtrShift;

        *(uint32*)(Item + Crypto.ItemHiOffset) = (uint32)(Packed >> 32);
        *(uint32*)(Item + Crypto.ItemLoOffset) = Bswap32((uint32)(Packed & 0xFFFFFFFFull) ^ Crypto.ItemLoKey);

        assert(DecryptObjectItemPtr(Item) == Ptr);
    }

    // FName index : ((bswap32(raw-1) ^ 0xB8171D6F) + 1)
    {
        const int32 Plain = 0x1F00;
        const uint32 Stored = Bswap32(((uint32)Plain - 1) ^ Crypto.NameIndexKey) + 1;
        FName N((int32)Stored);
        assert(N.GetDisplayIndex() == Plain);
    }

    // FieldPtr: bit0 clear -> plaintext passes through untouched
    {
        alignas(8) uint8_t Holder[0x10] = {};
        const uint64 PlainPtr = 0x00007FF612345000ull;

        *(uint64*)Holder = PlainPtr;
        assert((uint64)ReadFieldPtr(Holder, 0) == PlainPtr);
    }

    // FieldPtr parity against the dump's FortEncryption::DecryptFieldPtr
    {
        const uint64 U64s[] = {
            0x00007FF612345001ull, 0x0000000012345679ull, 0xFFFFFFFFFFFFFFFFull,
            0x00007FF6DEADBEEFull, 0x8000000000000001ull, 0x1ull,
        };
        for (uint64 Raw : U64s)
        {
            alignas(8) uint8_t Holder[0x10] = {};
            *(uint64*)Holder = Raw;
            assert((uint64)ReadFieldPtr(Holder, 0) == RefFieldPtr42(Raw));
        }
    }
}

int main()
{
    Test38();
    Test42();
    printf("crypto self-test: ok\n");
    return 0;
}
