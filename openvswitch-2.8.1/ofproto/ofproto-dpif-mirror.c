/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <config.h>

#include "ofproto-dpif-mirror.h"

#include <errno.h>

#include "cmap.h"
#include "hmapx.h"
#include "ofproto.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_mirror);

#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);

/* 桥镜像管理描述控制块 */
struct mbridge {
    struct mirror *mirrors[MAX_MIRRORS];/* 镜像描述控制块 */
    struct cmap mbundles;/* 桥镜像的端口挂载链表 */

    bool need_revalidate;/* 镜像配置是否发生变化，如果发生变化的话，设置true，等待重新配置 */
    bool has_mirrors;/* 是否存在镜像策略 */

    struct ovs_refcount ref_cnt;/* 桥镜像引用计数 */
};
/* 端口镜像描述控制块 */
struct mbundle {
    struct cmap_node cmap_node; /* In parent 'mbridge' map. 挂载到其所属的桥镜像控制块端口链表上 */
    struct ofbundle *ofbundle;  /* 指向其对等的openflow描述控制块 */

    mirror_mask_t src_mirrors;  /* Mirrors triggered when packet received. 以该端口为接收镜像的镜像策略掩码*/
    mirror_mask_t dst_mirrors;  /* Mirrors triggered when packet sent. 以该端口为发送镜像的镜像策略掩码*/
    mirror_mask_t mirror_out;   /* Mirrors that output to this mbundle. 以该端口为发送接口的镜像策略掩码*/
};
/* 镜像描述控制块，挂载到其所属的桥镜像数组中 */
struct mirror {
    struct mbridge *mbridge;    /* Owning ofproto.指向其所属的桥 */
    size_t idx;                 /* In ofproto's "mirrors" array.桥镜像数组中的下标 */
    void *aux;                  /* Key supplied by ofproto's client. 辅助数据，来自于用户，一般是配置的mirror结构体，用于区分每一个镜像策略*/

    /* Selection criteria. */
    struct hmapx srcs;          /* Contains "struct mbundle*"s. */
    struct hmapx dsts;          /* Contains "struct mbundle*"s. */

    /* This is accessed by handler threads assuming RCU protection (see
     * mirror_get()), but can be manipulated by mirror_set() without any
     * explicit synchronization. */
    OVSRCU_TYPE(unsigned long *) vlans;       /* Bitmap of chosen VLANs, NULL
                                               * selects all. */

    /* Output (exactly one of out == NULL and out_vlan == -1 is true). */
    struct mbundle *out;        /* Output port or NULL. */
    int out_vlan;               /* Output VLAN or -1. */
    uint16_t snaplen;           /* Max per mirrored packet size in byte,
                                   set to 0 equals 65535. 最大允许的单个报文的长度*/
    mirror_mask_t dup_mirrors;  /* Bitmap of mirrors with the same output. */

    /* Counters. */
    int64_t packet_count;       /* Number of packets sent. 镜像报文统计*/
    int64_t byte_count;         /* Number of bytes sent. 镜像字节统计*/
};

static struct mirror *mirror_lookup(struct mbridge *, void *aux);
static struct mbundle *mbundle_lookup(const struct mbridge *,
                                      struct ofbundle *);
static void mbundle_lookup_multiple(const struct mbridge *, struct ofbundle **,
                                  size_t n_bundles, struct hmapx *mbundles);
static int mirror_scan(struct mbridge *);
static void mirror_update_dups(struct mbridge *);
/* 创建桥镜像控制块 */
struct mbridge *
mbridge_create(void)
{
    struct mbridge *mbridge;
	/* 分配资源 */
    mbridge = xzalloc(sizeof *mbridge);
	/* 初始化其引用计数 */
    ovs_refcount_init(&mbridge->ref_cnt);
	/* 初始化其端口链表 */
    cmap_init(&mbridge->mbundles);
    return mbridge;/* 返回桥镜像控制块首地址 */
}
/* mbridge的引用计数加1 */
struct mbridge *
mbridge_ref(const struct mbridge *mbridge_)
{
    struct mbridge *mbridge = CONST_CAST(struct mbridge *, mbridge_);
    if (mbridge) {
        ovs_refcount_ref(&mbridge->ref_cnt);
    }
    return mbridge;
}
/* mbridge引用计数减1，当引用计数为0时，将其资源回收 */
void
mbridge_unref(struct mbridge *mbridge)
{
    struct mbundle *mbundle;
    size_t i;

    if (!mbridge) {/* 空指针判断 */
        return;
    }
	/* 返回原始引用计数，然后将引用计数减1 */
    if (ovs_refcount_unref(&mbridge->ref_cnt) == 1) {/* 原始引用计数为1，说明本次减掉之后就没有人引用该控制块了，可以释放 */
        for (i = 0; i < MAX_MIRRORS; i++) {/* 遍历镜像控制数组 */
            if (mbridge->mirrors[i]) {/* 如果不为空的话将其资源回收 */
                mirror_destroy(mbridge, mbridge->mirrors[i]->aux);/* 这段代码写的不好 */
            }
        }

        CMAP_FOR_EACH (mbundle, cmap_node, &mbridge->mbundles) {
            mbridge_unregister_bundle(mbridge, mbundle->ofbundle);
        }

        cmap_destroy(&mbridge->mbundles);
        ovsrcu_postpone(free, mbridge);
    }
}
/* 判断一个网桥是否存在镜像策略 */
bool
mbridge_has_mirrors(struct mbridge *mbridge)
{
    return mbridge ? mbridge->has_mirrors : false;
}

/* Returns true if configurations changes in 'mbridge''s mirrors require
 * revalidation, and resets the revalidation flag to false. */
 /* 判断网桥的镜像策略是否发生变化，如果发生变化则需要进行重新配置，返回true，然后将标志复位 */
bool
mbridge_need_revalidate(struct mbridge *mbridge)
{
    bool need_revalidate = mbridge->need_revalidate;
    mbridge->need_revalidate = false;
    return need_revalidate;
}

/* 给一个镜像策略添加端口 */
void
mbridge_register_bundle(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle;

    mbundle = xzalloc(sizeof *mbundle);
    mbundle->ofbundle = ofbundle;
    cmap_insert(&mbridge->mbundles, &mbundle->cmap_node,
                hash_pointer(ofbundle, 0));
}

/* 去掉镜像策略的端口 */
void
mbridge_unregister_bundle(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    size_t i;

    if (!mbundle) {
        return;
    }

    for (i = 0; i < MAX_MIRRORS; i++) {/* 遍历每一个策略 */
        struct mirror *m = mbridge->mirrors[i];
        if (m) {
            if (m->out == mbundle) {/* 查看策略的出端口是否为该端口 */
                mirror_destroy(mbridge, m->aux);/* 销毁该策略 */
            } else if (hmapx_find_and_delete(&m->srcs, mbundle)/* 查看源端口是否存在该策略中 */
                       || hmapx_find_and_delete(&m->dsts, mbundle)) {/* 查看是否该策略的出镜像接口 */
                mbridge->need_revalidate = true;/* 设置配置变更标志 */
            }
        }
    }

    cmap_remove(&mbridge->mbundles, &mbundle->cmap_node,/* 将该端口从桥中删除 */
                hash_pointer(ofbundle, 0));
    ovsrcu_postpone(free, mbundle);/* 释放其描述控制块 */
}
/* 获取镜像的出接口掩码 */
mirror_mask_t
mirror_bundle_out(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->mirror_out : 0;
}
/* 获取接收镜像的端口掩码 */
mirror_mask_t
mirror_bundle_src(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->src_mirrors : 0;
}
/* 获取发送镜像端口掩码 */
mirror_mask_t
mirror_bundle_dst(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->dst_mirrors : 0;
}
/* 设置镜像策略 */
int
mirror_set(struct mbridge *mbridge, void *aux, const char *name,
           struct ofbundle **srcs, size_t n_srcs,/* 接收镜像端口的个数 */
           struct ofbundle **dsts, size_t n_dsts,/* 发送镜像接口的个数 */
           unsigned long *src_vlans, struct ofbundle *out_bundle,/* 出接口 */
           uint16_t snaplen,/* 最大允许镜像的单个报文大小 */
           uint16_t out_vlan)/* 出接口VLAN */
{
    struct mbundle *mbundle, *out;
    mirror_mask_t mirror_bit;
    struct mirror *mirror;
    struct hmapx srcs_map;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts_map;          /* Contains "struct ofbundle *"s. */

    mirror = mirror_lookup(mbridge, aux);/* 根据辅助信息查找镜像策略 */
    if (!mirror) {/* 没有找到的话需要新建一个 */
        int idx;

        idx = mirror_scan(mbridge);/* 找到第一个可用的id */
        if (idx < 0) {
            VLOG_WARN("maximum of %d port mirrors reached, cannot create %s",
                      MAX_MIRRORS, name);
            return EFBIG;
        }
		/* 分配控制块，并初始化一些值 */
        mirror = mbridge->mirrors[idx] = xzalloc(sizeof *mirror);
        mirror->mbridge = mbridge;
        mirror->idx = idx;
        mirror->aux = aux;
        mirror->out_vlan = -1;
        mirror->snaplen = 0;
    }
	/* 获取镜像的VLAN掩码表 */
    unsigned long *vlans = ovsrcu_get(unsigned long *, &mirror->vlans);

    /* Get the new configuration. */
	/* 如果存在新的出接口。新销毁老的出接口 */
    if (out_bundle) {
        out = mbundle_lookup(mbridge, out_bundle);
        if (!out) {
            mirror_destroy(mbridge, mirror->aux);
            return EINVAL;
        }
        out_vlan = -1;
    } else {
        out = NULL;
    }
    mbundle_lookup_multiple(mbridge, srcs, n_srcs, &srcs_map);/* 查找所有的端口与输入相同的接口，为后续比较做准备 */
    mbundle_lookup_multiple(mbridge, dsts, n_dsts, &dsts_map);

    /* If the configuration has not changed, do nothing. */
    if (hmapx_equals(&srcs_map, &mirror->srcs)/* 判断需要配置的信息是否已经包含在了原有的配置中了，如果是则返回 */
        && hmapx_equals(&dsts_map, &mirror->dsts)
        && vlan_bitmap_equal(vlans, src_vlans)
        && mirror->out == out
        && mirror->out_vlan == out_vlan
        && mirror->snaplen == snaplen)
    {
        hmapx_destroy(&srcs_map);
        hmapx_destroy(&dsts_map);
        return 0;
    }

    /* XXX: Not sure if these need to be thread safe. */
	/* 更新新的配置 */
    hmapx_swap(&srcs_map, &mirror->srcs);
    hmapx_destroy(&srcs_map);

    hmapx_swap(&dsts_map, &mirror->dsts);
    hmapx_destroy(&dsts_map);

    if (vlans || src_vlans) {
        ovsrcu_postpone(free, vlans);
        vlans = vlan_bitmap_clone(src_vlans);
        ovsrcu_set(&mirror->vlans, vlans);
    }

    mirror->out = out;/* 出接口配置 */
    mirror->out_vlan = out_vlan;
    mirror->snaplen = snaplen;

    /* Update mbundles. */
	/* 跟新mbundles的对应镜像策略信息 */
    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;/* 获取该策略的索引掩码 */
    CMAP_FOR_EACH (mbundle, cmap_node, &mirror->mbridge->mbundles) {/* 遍历该桥的每一个镜像端口 */
        if (hmapx_contains(&mirror->srcs, mbundle)) {/* 该端口是否在该镜像策略的输入端口中 */
            mbundle->src_mirrors |= mirror_bit;/* 或上策略掩码 */
        } else {
            mbundle->src_mirrors &= ~mirror_bit;
        }

        if (hmapx_contains(&mirror->dsts, mbundle)) {/* 更新以该接口为发送镜像的镜像策略掩码 */
            mbundle->dst_mirrors |= mirror_bit;
        } else {
            mbundle->dst_mirrors &= ~mirror_bit;
        }

        if (mirror->out == mbundle) {/* 更新引用该接口为发送接口的镜像策略掩码 */
            mbundle->mirror_out |= mirror_bit;
        } else {
            mbundle->mirror_out &= ~mirror_bit;
        }
    }

    mbridge->has_mirrors = true;
    mirror_update_dups(mbridge);

    return 0;
}
/* 镜像策略资源回收 */
void
mirror_destroy(struct mbridge *mbridge, void *aux)
{
    struct mirror *mirror = mirror_lookup(mbridge, aux);/* 根据辅助信息找到其对应的镜像描述控制块 */
    mirror_mask_t mirror_bit;
    struct mbundle *mbundle;
    int i;

    if (!mirror) {/* 没找到的话直接返回 */
        return;
    }

    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;/* 将下标转换为位掩码 */
    CMAP_FOR_EACH (mbundle, cmap_node, &mbridge->mbundles) {/* 遍历桥下的每一个mbundle */
        mbundle->src_mirrors &= ~mirror_bit;/* 去掉该镜像的掩码bit */
        mbundle->dst_mirrors &= ~mirror_bit;/* 去掉该镜像的掩码bit */
        mbundle->mirror_out &= ~mirror_bit;/* 去掉该镜像的掩码bit */
    }

    hmapx_destroy(&mirror->srcs);
    hmapx_destroy(&mirror->dsts);

    unsigned long *vlans = ovsrcu_get(unsigned long *, &mirror->vlans);
    if (vlans) {
        ovsrcu_postpone(free, vlans);
    }

    mbridge->mirrors[mirror->idx] = NULL;
    /* mirror_get() might have just read the pointer, so we must postpone the
     * free. 采用rcu释放该镜像策略控制块*/
    ovsrcu_postpone(free, mirror);

    mirror_update_dups(mbridge);

	/* 判断该mbridge是否还有镜像策略 */
    mbridge->has_mirrors = false;
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (mbridge->mirrors[i]) {
            mbridge->has_mirrors = true;
            break;
        }
    }
}
/* 获取镜像的统计信息 */
int
mirror_get_stats(struct mbridge *mbridge, void *aux, uint64_t *packets,
                 uint64_t *bytes)
{
    struct mirror *mirror = mirror_lookup(mbridge, aux);/* 获取镜像策略 */

    if (!mirror) {
        *packets = *bytes = UINT64_MAX;
        return 0;
    }

    *packets = mirror->packet_count;
    *bytes = mirror->byte_count;

    return 0;
}

/* 统计信息更新 */
void
mirror_update_stats(struct mbridge *mbridge, mirror_mask_t mirrors,
                    uint64_t packets, uint64_t bytes)
{
    if (!mbridge || !mirrors) {
        return;
    }
	/* 跟新每一个bit对应的镜像的统计信息 */
    for (; mirrors; mirrors = zero_rightmost_1bit(mirrors)) {
        struct mirror *m;

        m = mbridge->mirrors[raw_ctz(mirrors)];

        if (!m) {
            /* In normal circumstances 'm' will not be NULL.  However,
             * if mirrors are reconfigured, we can temporarily get out
             * of sync in facet_revalidate().  We could "correct" the
             * mirror list before reaching here, but doing that would
             * not properly account the traffic stats we've currently
             * accumulated for previous mirror configuration. */
            continue;
        }

        /* XXX: This is not thread safe, yet we are calling these from the
         * handler and revalidation threads.  But then, maybe these stats do
         * not need to be very accurate. */
        m->packet_count += packets;
        m->byte_count += bytes;
    }
}

/* Retrieves the mirror numbered 'index' in 'mbridge'.  Returns true if such a
 * mirror exists, false otherwise.
 *
 * If successful, '*vlans' receives the mirror's VLAN membership information,
 * either a null pointer if the mirror includes all VLANs or a 4096-bit bitmap
 * in which a 1-bit indicates that the mirror includes a particular VLAN,
 * '*dup_mirrors' receives a bitmap of mirrors whose output duplicates mirror
 * 'index', '*out' receives the output ofbundle (if any), and '*out_vlan'
 * receives the output VLAN (if any).
 *
 * Everything returned here is assumed to be RCU protected.
 * 获取指定索引的镜像策略信息，包括vlanbit，重复bit，输出端口，最大长度，输出VLAN
 */
bool
mirror_get(struct mbridge *mbridge, int index, const unsigned long **vlans,
           mirror_mask_t *dup_mirrors, struct ofbundle **out,
           int *snaplen, int *out_vlan)
{
    struct mirror *mirror;

    if (!mbridge) {
        return false;
    }

    mirror = mbridge->mirrors[index];
    if (!mirror) {
        return false;
    }
    /* Assume 'mirror' is RCU protected, i.e., it will not be freed until this
     * thread quiesces. */

    *vlans = ovsrcu_get(unsigned long *, &mirror->vlans);
    *dup_mirrors = mirror->dup_mirrors;
    *out = mirror->out ? mirror->out->ofbundle : NULL;
    *out_vlan = mirror->out_vlan;
    *snaplen = mirror->snaplen;
    return true;
}

/* Helpers. */
/* 根据ofboundle查找mbundle */
static struct mbundle *
mbundle_lookup(const struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle;
    uint32_t hash = hash_pointer(ofbundle, 0);

    CMAP_FOR_EACH_WITH_HASH (mbundle, cmap_node, hash, &mbridge->mbundles) {
        if (mbundle->ofbundle == ofbundle) {
            return mbundle;
        }
    }
    return NULL;
}

/* Looks up each of the 'n_ofbundles' pointers in 'ofbundles' as mbundles and
 * adds the ones that are found to 'mbundles'. */
 /* 查找多个mbundle */
static void
mbundle_lookup_multiple(const struct mbridge *mbridge,
                        struct ofbundle **ofbundles, size_t n_ofbundles,
                        struct hmapx *mbundles)
{
    size_t i;

    hmapx_init(mbundles);
    for (i = 0; i < n_ofbundles; i++) {
        struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundles[i]);
        if (mbundle) {
            hmapx_add(mbundles, mbundle);
        }
    }
}
/* 找到第一个可用的镜像策略索引 */
static int
mirror_scan(struct mbridge *mbridge)
{
    int idx;

    for (idx = 0; idx < MAX_MIRRORS; idx++) {
        if (!mbridge->mirrors[idx]) {
            return idx;
        }
    }
    return -1;
}
/* 根据辅助信息查找器对应的镜像策略 */
static struct mirror *
mirror_lookup(struct mbridge *mbridge, void *aux)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *mirror = mbridge->mirrors[i];
        if (mirror && mirror->aux == aux) {
            return mirror;
        }
    }

    return NULL;
}

/* Update the 'dup_mirrors' member of each of the mirrors in 'ofproto'. */
/* 更新有相同输出参数镜像策略掩码         */
static void
mirror_update_dups(struct mbridge *mbridge)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m = mbridge->mirrors[i];

        if (m) {
            m->dup_mirrors = MIRROR_MASK_C(1) << i;
        }
    }

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m1 = mbridge->mirrors[i];
        int j;

        if (!m1) {
            continue;
        }

        for (j = i + 1; j < MAX_MIRRORS; j++) {
            struct mirror *m2 = mbridge->mirrors[j];

            if (m2 && m1->out == m2->out && m1->out_vlan == m2->out_vlan) {
                m1->dup_mirrors |= MIRROR_MASK_C(1) << j;
                m2->dup_mirrors |= m1->dup_mirrors;
            }
        }
    }
}
