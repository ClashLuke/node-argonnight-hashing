/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018-2019 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2019 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>


#include "common/cpu/Cpu.h"
#include "common/net/Pool.h"
#include "crypto/Asm.h"
#include "Mem.h"
#include "rapidjson/document.h"
#include "workers/CpuThread.h"


#if defined(XMRIG_ARM)
#   include "crypto/CryptoNight_arm.h"
#else
#   include "crypto/CryptoNight_x86.h"
#endif


xmrig::CpuThread::CpuThread(size_t index, Algo algorithm, AlgoVariant av, Multiway multiway, int64_t affinity, int priority, bool softAES, bool prefetch, Assembly assembly) :
    m_algorithm(algorithm),
    m_av(av),
    m_assembly(assembly),
    m_prefetch(prefetch),
    m_softAES(softAES),
    m_priority(priority),
    m_affinity(affinity),
    m_multiway(multiway),
    m_index(index)
{
}


#ifndef XMRIG_NO_ASM
template<typename T, typename U>
static void patchCode(T dst, U src, const uint32_t iterations, const uint32_t mask)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(src);

    // Workaround for Visual Studio placing trampoline in debug builds.
#   if defined(_MSC_VER)
    if (p[0] == 0xE9) {
        p += *(int32_t*)(p + 1) + 5;
    }
#   endif

    size_t size = 0;
    while (*(uint32_t*)(p + size) != 0xDEADC0DE) {
        ++size;
    }
    size += sizeof(uint32_t);

    memcpy((void*) dst, (const void*) src, size);

    uint8_t* patched_data = reinterpret_cast<uint8_t*>(dst);
    for (size_t i = 0; i + sizeof(uint32_t) <= size; ++i) {
        switch (*(uint32_t*)(patched_data + i)) {
        case 0x100000:
            *(uint32_t*)(patched_data + i) = iterations;
            break;

        case 0x1FFFF0:
            *(uint32_t*)(patched_data + i) = mask;
            break;
        }
    }
}


void xmrig::CpuThread::patchAsmVariants()
{
    const int allocation_size = 65536;
    uint8_t *base = static_cast<uint8_t *>(Mem::allocateExecutableMemory(allocation_size));
    Mem::protectExecutableMemory(base, allocation_size);
    Mem::flushInstructionCache(base, allocation_size);
}
#endif


bool xmrig::CpuThread::isSoftAES(AlgoVariant av)
{
    return av == AV_SINGLE_SOFT || av == AV_DOUBLE_SOFT || av > AV_PENTA;
}


#ifndef XMRIG_NO_ASM
template<xmrig::Algo algo, xmrig::Variant variant>
static inline void add_asm_func(xmrig::CpuThread::cn_hash_fun(&asm_func_map)[xmrig::ALGO_MAX][xmrig::AV_MAX][xmrig::VARIANT_MAX][xmrig::ASM_MAX])
{
    asm_func_map[algo][xmrig::AV_SINGLE][variant][xmrig::ASM_INTEL] = cryptonight_single_hash_asm<algo, variant, xmrig::ASM_INTEL>;
    asm_func_map[algo][xmrig::AV_SINGLE][variant][xmrig::ASM_RYZEN] = cryptonight_single_hash_asm<algo, variant, xmrig::ASM_RYZEN>;
    asm_func_map[algo][xmrig::AV_SINGLE][variant][xmrig::ASM_BULLDOZER] = cryptonight_single_hash_asm<algo, variant, xmrig::ASM_BULLDOZER>;
}
#endif

xmrig::CpuThread::cn_hash_fun xmrig::CpuThread::fn(Algo algorithm, AlgoVariant av, Variant variant, Assembly assembly)
{
    assert(variant >= VARIANT_0 && variant < VARIANT_MAX);

#   ifndef XMRIG_NO_ASM
    if (assembly == ASM_AUTO) {
        assembly = Cpu::info()->assembly();
    }

    static cn_hash_fun asm_func_map[ALGO_MAX][AV_MAX][VARIANT_MAX][ASM_MAX] = {};
    static bool asm_func_map_initialized = false;

    if (!asm_func_map_initialized) {
        asm_func_map_initialized = true;
    }

    cn_hash_fun fun = asm_func_map[algorithm][av][variant][assembly];
    if (fun) {
        return fun;
    }
#   endif

    //constexpr const size_t count = 1;

    static const cn_hash_fun func_table[] = {
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_0>,
    };

   // static_assert(count == sizeof(func_table) / sizeof(func_table[0]), "func_table size mismatch");

    const size_t index = 0;

#   ifndef NDEBUG
    cn_hash_fun func = func_table[index];

    assert(index < sizeof(func_table) / sizeof(func_table[0]));
    assert(func != nullptr);

    return func;
#   else
    return func_table[index];
#   endif
}


xmrig::CpuThread *xmrig::CpuThread::createFromAV(size_t index, Algo algorithm, AlgoVariant av, int64_t affinity, int priority, Assembly assembly)
{
    assert(av > AV_AUTO && av < AV_MAX);

    int64_t cpuId = -1L;

    if (affinity != -1L) {
        size_t idx = 0;

        for (size_t i = 0; i < 64; i++) {
            if (!(affinity & (1ULL << i))) {
                continue;
            }

            if (idx == index) {
                cpuId = i;
                break;
            }

            idx++;
        }
    }

    return new CpuThread(index, algorithm, av, multiway(av), cpuId, priority, isSoftAES(av), false, assembly);
}


xmrig::CpuThread *xmrig::CpuThread::createFromData(size_t index, Algo algorithm, const CpuThread::Data &data, int priority, bool softAES)
{
    int av                  = AV_AUTO;
    const Multiway multiway = data.multiway;

    if (multiway <= DoubleWay) {
        av = softAES ? (multiway + 2) : multiway;
    }
    else {
        av = softAES ? (multiway + 5) : (multiway + 2);
    }

    assert(av > AV_AUTO && av < AV_MAX);

    return new CpuThread(index, algorithm, static_cast<AlgoVariant>(av), multiway, data.affinity, priority, softAES, false, data.assembly);
}


xmrig::CpuThread::Data xmrig::CpuThread::parse(const rapidjson::Value &object)
{
    Data data;

    const auto &multiway = object["low_power_mode"];
    if (multiway.IsBool()) {
        data.multiway = multiway.IsTrue() ? DoubleWay : SingleWay;
        data.valid    = true;
    }
    else if (multiway.IsUint()) {
        data.setMultiway(multiway.GetInt());
    }

    if (!data.valid) {
        return data;
    }

    const auto &affinity = object["affine_to_cpu"];
    if (affinity.IsUint64()) {
        data.affinity = affinity.GetInt64();
    }

#   ifndef XMRIG_NO_ASM
    data.assembly = Asm::parse(object["asm"]);
#   endif

    return data;
}


xmrig::IThread::Multiway xmrig::CpuThread::multiway(AlgoVariant av)
{
    switch (av) {
    case AV_SINGLE:
    case AV_SINGLE_SOFT:
        return SingleWay;

    default:
        break;
    }

    return SingleWay;
}


#ifdef APP_DEBUG
void xmrig::CpuThread::print() const
{
    LOG_DEBUG(GREEN_BOLD("CPU thread:   ") " index " WHITE_BOLD("%zu") ", multiway " WHITE_BOLD("%d") ", av " WHITE_BOLD("%d") ",",
              index(), static_cast<int>(multiway()), static_cast<int>(m_av));

#   ifndef XMRIG_NO_ASM
    LOG_DEBUG("               assembly: %s, affine_to_cpu: %" PRId64, Asm::toString(m_assembly), affinity());
#   else
    LOG_DEBUG("               affine_to_cpu: %" PRId64, affinity());
#   endif
}
#endif


#ifndef XMRIG_NO_API
rapidjson::Value xmrig::CpuThread::toAPI(rapidjson::Document &doc) const
{
    using namespace rapidjson;

    Value obj(kObjectType);
    auto &allocator = doc.GetAllocator();

    obj.AddMember("type",          "cpu", allocator);
    obj.AddMember("av",             m_av, allocator);
    obj.AddMember("low_power_mode", multiway(), allocator);
    obj.AddMember("affine_to_cpu",  affinity(), allocator);
    obj.AddMember("priority",       priority(), allocator);
    obj.AddMember("soft_aes",       isSoftAES(), allocator);

    return obj;
}
#endif


rapidjson::Value xmrig::CpuThread::toConfig(rapidjson::Document &doc) const
{
    using namespace rapidjson;

    Value obj(kObjectType);
    auto &allocator = doc.GetAllocator();

    obj.AddMember("low_power_mode", multiway(), allocator);
    obj.AddMember("affine_to_cpu",  affinity() == -1L ? Value(kFalseType) : Value(affinity()), allocator);

#   ifndef XMRIG_NO_ASM
    obj.AddMember("asm", Asm::toJSON(m_assembly), allocator);
#   endif

    return obj;
}
