from .aes_gcm import AES_GCM


def run_test():
    # NIST SP 800-38D – 128-bit key test vectors
    vectors = [
        {
            "name": "NIST Case 2: 128-bit key, 12-byte IV, no AAD",
            "key": "00000000000000000000000000000000",
            "iv":  "000000000000000000000000",
            "aad": "",
            "pt":  "00000000000000000000000000000000",
            "ct":  "0388dace60b6a392f328c2b971b2fe78",
            "tag": "ab6e47d42cec13bdf53a67b21257bddf",
        },
        {
            "name": "NIST Case 4: 128-bit key, 12-byte IV, with AAD",
            "key": "feffe9928665731c6d6a8f9467308308",
            "iv":  "cafebabefacedbaddecaf888",
            "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "pt": (
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            "ct": (
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091"
            ),
            "tag": "5bc94fbc3221a5db94fae95ae7121a47",
        },
        {
            "name": "NIST Case 5: 128-bit key, 8-byte IV, with AAD",
            "key": "feffe9928665731c6d6a8f9467308308",
            "iv":  "cafebabefacedbad",  # 8 bytes
            "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "pt": (
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            "ct": (
                "61353b4c2806934a777ff51fa22a4755"
                "699b2a714fcdc6f83766e5f97b6c7423"
                "73806900e49f24b22b097544d4896b42"
                "4989b5e1ebac0f07c23f4598"
            ),
            "tag": "3612d2e79e3b0785561be14aaca2fccb",
        },
        {
            "name": "NIST Case 6: 128-bit key, 60-byte IV, with AAD",
            "key": "feffe9928665731c6d6a8f9467308308",
            "iv": (
                "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b"
            ),
            "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "pt": (
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            "ct": (
                "8ce24998625615b603a033aca13fb894"
                "be9112a5c3a211a8ba262a3cca7e2ca7"
                "01e4a9a4fba43c90ccdcb281d48c7c6f"
                "d62875d2aca417034c34aee5"
            ),
            "tag": "619cc5aefffe0bfa462af43c1699d050",
        },
    ]

    print(f"{'TEST NAME':<65} | {'CT':<6} | {'TAG':<6} | {'DEC':<6}")

    for v in vectors:
        key = bytes.fromhex(v["key"])
        iv = bytes.fromhex(v["iv"])
        aad = bytes.fromhex(v["aad"])
        pt = bytes.fromhex(v["pt"])

        gcm = AES_GCM(key, iv, aad)

        # Encrypt
        ct_out, tag_out = gcm.encrypt_gcm(pt)

        ct_hex = ct_out.hex()
        tag_hex = tag_out.hex()

        ct_check = "PASS" if ct_hex == v["ct"] else "FAIL"
        tag_check = "PASS" if tag_hex == v["tag"] else "FAIL"

        # Decrypt + verify tag
        pt_dec = gcm.decrypt_gcm(ct_out, tag_out)
        dec_check = "PASS" if pt_dec == pt else "FAIL"

        print(f"{v['name']:<65} | {ct_check:<6} | {tag_check:<6} | {dec_check:<6}")

        if ct_check == "FAIL" or tag_check == "FAIL" or dec_check == "FAIL":
            print(f"   Expected CT:  {v['ct']}")
            print(f"   Got CT:       {ct_hex}")
            print(f"   Expected Tag: {v['tag']}")
            print(f"   Got Tag:      {tag_hex}")
            print(f"   PT match:     {dec_check}")


if __name__ == "__main__":
    run_test()
