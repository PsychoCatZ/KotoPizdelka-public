#!/usr/bin/env python3
"""Check the release DEX, not just ProGuard text, for Room's startup constructor.

Usage: python3 deploy/android/verify-workmanager-apk.py release.apk
No Android SDK or third-party Python packages required.
"""
import re
import struct
import sys
import zipfile


def has_constructor(data):
    assert data[:4] == b"dex\n", "Expected a standard DEX file"

    def u32(offset):
        return struct.unpack_from("<I", data, offset)[0]

    def uleb(offset):
        value = 0
        for shift in range(0, 35, 7):
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value, offset
        raise ValueError("Invalid ULEB128")

    string_count, strings_offset = struct.unpack_from("<II", data, 56)
    strings = []
    for index in range(string_count):
        _, start = uleb(u32(strings_offset + index * 4))
        end = data.index(b"\x00", start)
        strings.append(data[start:end])
    type_count, types_offset = struct.unpack_from("<II", data, 64)
    types = [strings[u32(types_offset + index * 4)] for index in range(type_count)]
    protos_offset = u32(76)
    methods_offset = u32(92)
    class_count, classes_offset = struct.unpack_from("<II", data, 96)
    expected = b"Landroidx/work/impl/WorkDatabase_Impl;"
    for index in range(class_count):
        class_offset = classes_offset + index * 32
        if types[u32(class_offset)] != expected:
            continue
        offset = u32(class_offset + 24)
        if not offset:
            return False
        counts = []
        for _ in range(4):
            count, offset = uleb(offset)
            counts.append(count)
        for _ in range(counts[0] + counts[1]):
            _, offset = uleb(offset)
            _, offset = uleb(offset)
        for count in counts[2:]:
            method_index = 0
            for _ in range(count):
                delta, offset = uleb(offset)
                access, offset = uleb(offset)
                code, offset = uleb(offset)
                method_index += delta
                owner, proto, name = struct.unpack_from(
                    "<HHI", data, methods_offset + method_index * 8
                )
                proto_offset = protos_offset + proto * 12
                parameters = u32(proto_offset + 8)
                if (types[owner] == expected and strings[name] == b"<init>"
                        and types[u32(proto_offset + 4)] == b"V"
                        and (not parameters or u32(parameters) == 0)
                        and access & 1 and not access & 8 and code):
                    return True
        return False
    return False


def verify(apk):
    with zipfile.ZipFile(apk) as archive:
        dex_files = [name for name in archive.namelist()
                     if re.fullmatch(r"classes\d*\.dex", name)]
        if not any(has_constructor(archive.read(name)) for name in dex_files):
            raise ValueError("WorkDatabase_Impl public zero-argument constructor missing")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: verify-workmanager-apk.py release.apk")
    try:
        verify(sys.argv[1])
    except (ValueError, AssertionError) as error:
        sys.exit("FAIL: " + str(error))
    print("PASS: packaged WorkDatabase_Impl has public <init>()V with executable code")
