/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#define main native_bridge_main
#include "../src/gtk/gtk-native.c"
#undef main
#include "host-test-util.h"

static GskRenderNode *frame(Surface *surface,
                            const uint32_t *data,
                            size_t words)
{
    GHashTable *next = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, free_scene_node);
    Decoder decoder = {.data = (const uint8_t *) data,
                       .size = words * 4,
                       .surface = surface,
                       .next = next};
    GskRenderNode *node = decode_node(&decoder, 0);
    if (!node || decoder.failed || decoder.pos != decoder.size) {
        if (node)
            gsk_render_node_unref(node);
        g_hash_table_unref(next);
        return NULL;
    }
    g_hash_table_unref(surface->nodes);
    surface->nodes = next;
    return node;
}

int main(void)
{
    Surface surface = {0};
    surface.nodes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                          free_scene_node);
    const uint32_t initial[] = {BROADWAY_NODE_CONTAINER,
                                1,
                                1,
                                BROADWAY_NODE_COLOR,
                                2,
                                0,
                                0,
                                0x41200000,
                                0x41200000,
                                0xffff0000};
    GskRenderNode *node = frame(&surface, initial, G_N_ELEMENTS(initial));
    host_check(node != NULL, "initial scene", "the scene must decode");
    if (node)
        gsk_render_node_unref(node);
    const uint32_t parent[] = {BROADWAY_NODE_REUSE, 1};
    node = frame(&surface, parent, G_N_ELEMENTS(parent));
    host_check(node != NULL, "parent reuse", "the previous root must survive");
    if (node)
        gsk_render_node_unref(node);
    const uint32_t descendant[] = {BROADWAY_NODE_REUSE, 2};
    node = frame(&surface, descendant, G_N_ELEMENTS(descendant));
    host_check(node != NULL, "descendant reuse",
               "reusing a parent must retain its descendants");
    if (node) {
        const GdkRGBA *rgba = gsk_color_node_get_color(node);
        graphene_rect_t bounds;
        gsk_render_node_get_bounds(node, &bounds);
        host_check(rgba->red == 1 && rgba->green == 0 && rgba->blue == 0 &&
                       bounds.size.width == 10 && bounds.size.height == 10,
                   "retained drawing",
                   "reused nodes must preserve color and bounds");
        gsk_render_node_unref(node);
    }
    const uint32_t truncated[] = {BROADWAY_NODE_COLOR, 3, 0, 0, 0x41200000};
    node = frame(&surface, truncated, G_N_ELEMENTS(truncated));
    host_check(node == NULL, "truncated color",
               "an incomplete payload must be rejected");
    const uint32_t invalid_count[] = {BROADWAY_NODE_CONTAINER, 4, UINT32_MAX};
    node = frame(&surface, invalid_count, G_N_ELEMENTS(invalid_count));
    host_check(node == NULL, "container extent",
               "the child count must fit the payload");
    const uint32_t missing[] = {BROADWAY_NODE_REUSE, 99};
    node = frame(&surface, missing, G_N_ELEMENTS(missing));
    host_check(node == NULL, "missing reuse",
               "an unknown node must be rejected");
    node = frame(&surface, descendant, G_N_ELEMENTS(descendant));
    host_check(node != NULL, "failed frame rollback",
               "invalid frames must not discard the live scene");
    if (node)
        gsk_render_node_unref(node);
    g_hash_table_unref(surface.nodes);
    return host_summary("gtk-native-host");
}
