{
    "targets": [
        {
            "target_name": "cryptonight-hashing",
            "sources": [
                '<!@(uname -a | grep "x86_64" >/dev/null && echo "xmrig/crypto/asm/cn_main_loop.S" || echo)',
                '<!@(uname -a | grep "x86_64" >/dev/null && echo "xmrig/common/cpu/Cpu.cpp" || echo)',
                '<!@(uname -a | grep "x86_64" >/dev/null && echo "xmrig/common/cpu/BasicCpuInfo.cpp" || echo)',
                '<!@(uname -a | grep "x86_64" >/dev/null || echo "xmrig/common/cpu/BasicCpuInfo_arm.cpp" || echo)',
                "multihashing.cc",
                "xmrig/extra.cpp",
                "xmrig/Mem.cpp",
                "xmrig/Mem_unix.cpp",
                "xmrig/crypto/c_blake256.c",
                "xmrig/crypto/c_groestl.c",
                "xmrig/crypto/c_jh.c",
                "xmrig/crypto/c_skein.c",
                "xmrig/common/crypto/keccak.cpp",
                "xmrig/src/crypto/argon2/argon2.c",
                "xmrig/src/crypto/argon2/blake2b.c",
                "xmrig/src/crypto/argon2/core.c",
                "xmrig/src/crypto/argon2/encoding.c",
                "xmrig/src/crypto/argon2/genkat.c",
                "xmrig/src/crypto/argon2/ref.c",
                "xmrig/src/crypto/argon2/thread.c"
            ],
            "include_dirs": [
                "xmrig",
                "xmrig/3rdparty",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_c": [
                '<!@(uname -a | grep "aarch64" >/dev/null && echo "-march=armv8-a+crypto -flax-vector-conversions -DXMRIG_ARM=1" || (uname -a | grep "armv7" >/dev/null && echo "-mfpu=neon -flax-vector-conversions -DXMRIG_ARM=1" || echo "-march=native"))',
                '<!@(grep Intel /proc/cpuinfo >/dev/null && echo -DCPU_INTEL || (grep AMD /proc/cpuinfo >/dev/null || echo))>',
                "-std=gnu11      -fPIC -DNDEBUG -Ofast -fno-fast-math -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ],
            "cflags_cc": [
                '<!@(uname -a | grep "aarch64" >/dev/null && echo "-march=armv8-a+crypto -flax-vector-conversions -DXMRIG_ARM=1" || (uname -a | grep "armv7" >/dev/null && echo "-mfpu=neon -flax-vector-conversions -DXMRIG_ARM=1" || echo "-march=native"))',
                '<!@(grep Intel /proc/cpuinfo >/dev/null && echo -DCPU_INTEL || (grep AMD /proc/cpuinfo >/dev/null || echo))>',
                "-std=gnu++11 -s -fPIC -DNDEBUG -Ofast -fno-fast-math -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ]
        }
    ]
}
