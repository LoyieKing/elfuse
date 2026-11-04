/*
 * Native macOS presentation for the GTK 4 Broadway local surface protocol.
 * Protocol layout: GTK 4.24 gdk/broadway/broadway-protocol.h
 * (LGPL-2.1-or-later).
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtk/gtk.h>
#include <gio/gunixfdmessage.h>
#include <glib-unix.h>

#include "gtk/native-protocol.h"
#include "proved/align.h"

#define MAX_MESSAGE (16u * 1024u * 1024u)
#define MAX_TEXTURE (64u * 1024u * 1024u)
#define MAX_TEXTURE_TOTAL (256u * 1024u * 1024u)
#define MAX_NODES 65536u
#define MAX_SURFACES 128u
#define MAX_DEPTH 128u

typedef struct client Client;
typedef struct {
    unsigned refs;
    size_t bytes;
} TextureBudget;

typedef struct surface Surface;

struct client {
    GSocketConnection *connection;
    GByteArray *buffer;
    GQueue fds;
    GHashTable *textures;
    GHashTable *surfaces;
    TextureBudget *texture_budget;
    uint32_t serial;
    uint32_t pointer_surface;
    int pointer_x, pointer_y;
    GdkModifierType modifiers;
    GSource *source;
};

struct surface {
    Client *client;
    uint32_t id;
    GtkWindow *window;
    GtkWidget *canvas;
    GHashTable *nodes;
    GskRenderNode *root;
    int x, y, width, height;
    GQueue frames;
    guint frame_source;
};

typedef struct {
    unsigned refs;
    GskRenderNode *node;
    GArray *children;
} SceneNode;

static void free_scene_node(gpointer data)
{
    SceneNode *entry = data;
    if (--entry->refs)
        return;
    gsk_render_node_unref(entry->node);
    g_array_unref(entry->children);
    g_free(entry);
}

typedef struct {
    const uint8_t *data;
    size_t size, pos;
    unsigned count;
    bool failed;
    Surface *surface;
    GHashTable *next;
    GArray *children;
} Decoder;

typedef struct {
    size_t bytes;
    TextureBudget *budget;
} Texture;

static GMainLoop *loop;
static GList *clients;
static GPid guest_pid;
static int guest_status;
static uint32_t next_surface = 1;
static char *runtime_dir;
static char *socket_path;

static uint32_t png_word(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | p[3];
}

static void release_texture_budget(gpointer data)
{
    Texture *t = data;
    t->budget->bytes -= t->bytes;
    if (--t->budget->refs == 0)
        g_free(t->budget);
    g_free(t);
}

static uint32_t word(Decoder *d)
{
    uint32_t v = 0;
    if (!window_fits(d->pos, sizeof(v), d->size)) {
        d->failed = true;
        return 0;
    }
    memcpy(&v, d->data + d->pos, sizeof(v));
    d->pos += sizeof(v);
    return GUINT32_FROM_LE(v);
}

static float number(Decoder *d)
{
    uint32_t bits = word(d);
    float v;
    memcpy(&v, &bits, sizeof(v));
    if (!isfinite(v) || fabsf(v) > 1000000.0f) {
        d->failed = true;
        return 0;
    }
    return v;
}

static graphene_rect_t rectangle(Decoder *d)
{
    float x = number(d), y = number(d), w = number(d), h = number(d);
    if (w < 0 || h < 0)
        d->failed = true;
    return GRAPHENE_RECT_INIT(x, y, w, h);
}

static GdkRGBA color(Decoder *d)
{
    uint32_t c = word(d);
    return (GdkRGBA) {((c >> 16) & 255) / 255.0f, ((c >> 8) & 255) / 255.0f,
                      (c & 255) / 255.0f, (c >> 24) / 255.0f};
}

static GskRoundedRect rounded(Decoder *d)
{
    GskRoundedRect r;
    r.bounds = rectangle(d);
    for (unsigned i = 0; i < 4; i++) {
        r.corner[i].width = number(d);
        r.corner[i].height = number(d);
        if (r.corner[i].width < 0 || r.corner[i].height < 0)
            d->failed = true;
    }
    return r;
}

static GskRenderNode *translate_node(GskRenderNode *child, float x, float y)
{
    graphene_point_t p = GRAPHENE_POINT_INIT(x, y);
    GskTransform *t = gsk_transform_translate(NULL, &p);
    GskRenderNode *node = gsk_transform_node_new(child, t);
    gsk_transform_unref(t);
    return node;
}

static bool retain_subtree(Decoder *d, uint32_t id, unsigned depth)
{
    if (g_hash_table_contains(d->next, GUINT_TO_POINTER(id)))
        return true;
    SceneNode *entry =
        g_hash_table_lookup(d->surface->nodes, GUINT_TO_POINTER(id));
    if (!entry || depth >= MAX_DEPTH || g_hash_table_size(d->next) >= MAX_NODES)
        return false;
    entry->refs++;
    g_hash_table_insert(d->next, GUINT_TO_POINTER(id), entry);
    for (unsigned i = 0; i < entry->children->len; i++)
        if (!retain_subtree(d, g_array_index(entry->children, uint32_t, i),
                            depth + 1))
            return false;
    return true;
}

static GskRenderNode *decode_node(Decoder *d, unsigned depth)
{
    if (d->failed || depth >= MAX_DEPTH || ++d->count > MAX_NODES) {
        d->failed = true;
        return NULL;
    }
    uint32_t type = word(d), id = word(d);
    GskRenderNode *node = NULL, *child = NULL;
    GArray *parent = d->children;
    GArray *children = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    d->children = children;
    switch (type) {
    case BROADWAY_NODE_REUSE: {
        SceneNode *entry =
            g_hash_table_lookup(d->surface->nodes, GUINT_TO_POINTER(id));
        if (entry && retain_subtree(d, id, depth))
            node = gsk_render_node_ref(entry->node);
        break;
    }
    case BROADWAY_NODE_TEXTURE: {
        graphene_rect_t r = rectangle(d);
        GdkTexture *texture = g_hash_table_lookup(d->surface->client->textures,
                                                  GUINT_TO_POINTER(word(d)));
        if (!d->failed && texture)
            node = gsk_texture_node_new(texture, &r);
        break;
    }
    case BROADWAY_NODE_COLOR: {
        graphene_rect_t r = rectangle(d);
        GdkRGBA c = color(d);
        if (!d->failed)
            node = gsk_color_node_new(&c, &r);
        break;
    }
    case BROADWAY_NODE_BORDER: {
        GskRoundedRect r = rounded(d);
        float widths[4];
        GdkRGBA colors[4];
        for (unsigned i = 0; i < 4; i++) {
            widths[i] = number(d);
            if (widths[i] < 0)
                d->failed = true;
        }
        for (unsigned i = 0; i < 4; i++)
            colors[i] = color(d);
        if (!d->failed)
            node = gsk_border_node_new(&r, widths, colors);
        break;
    }
    case BROADWAY_NODE_OUTSET_SHADOW:
    case BROADWAY_NODE_INSET_SHADOW: {
        GskRoundedRect r = rounded(d);
        GdkRGBA c = color(d);
        float x = number(d), y = number(d), spread = number(d),
              blur = number(d);
        if (blur < 0)
            d->failed = true;
        if (!d->failed)
            node = type == BROADWAY_NODE_OUTSET_SHADOW
                       ? gsk_outset_shadow_node_new(&r, &c, x, y, spread, blur)
                       : gsk_inset_shadow_node_new(&r, &c, x, y, spread, blur);
        break;
    }
    case BROADWAY_NODE_CONTAINER: {
        unsigned n = word(d);
        if (n > MAX_NODES || n > (d->size - d->pos) / 8) {
            d->failed = true;
            break;
        }
        GskRenderNode **children = g_new0(GskRenderNode *, n);
        unsigned i;
        for (i = 0; i < n; i++) {
            children[i] = decode_node(d, depth + 1);
            if (!children[i])
                break;
        }
        if (i == n && !d->failed)
            node = gsk_container_node_new(children, n);
        for (unsigned j = 0; j < i; j++)
            gsk_render_node_unref(children[j]);
        g_free(children);
        break;
    }
    case BROADWAY_NODE_CLIP:
    case BROADWAY_NODE_ROUNDED_CLIP: {
        GskRoundedRect r;
        if (type == BROADWAY_NODE_ROUNDED_CLIP)
            r = rounded(d);
        else {
            memset(&r, 0, sizeof(r));
            r.bounds = rectangle(d);
        }
        child = decode_node(d, depth + 1);
        if (child && !d->failed) {
            GskRenderNode *moved =
                translate_node(child, r.bounds.origin.x, r.bounds.origin.y);
            node = type == BROADWAY_NODE_CLIP
                       ? gsk_clip_node_new(moved, &r.bounds)
                       : gsk_rounded_clip_node_new(moved, &r);
            gsk_render_node_unref(moved);
        }
        break;
    }
    case BROADWAY_NODE_LINEAR_GRADIENT: {
        graphene_rect_t r = rectangle(d);
        float sx = number(d), sy = number(d), ex = number(d), ey = number(d);
        graphene_point_t start = GRAPHENE_POINT_INIT(sx, sy);
        graphene_point_t end = GRAPHENE_POINT_INIT(ex, ey);
        unsigned n = word(d);
        if (n < 2 || n > 4096 || n > (d->size - d->pos) / 8) {
            d->failed = true;
            break;
        }
        GskColorStop *stops = g_new(GskColorStop, n);
        for (unsigned i = 0; i < n; i++) {
            stops[i].offset = number(d);
            stops[i].color = color(d);
            if (stops[i].offset < 0 || stops[i].offset > 1 ||
                (i && stops[i].offset < stops[i - 1].offset))
                d->failed = true;
        }
        if (!d->failed)
            node = gsk_linear_gradient_node_new(&r, &start, &end, stops, n);
        g_free(stops);
        break;
    }
    case BROADWAY_NODE_SHADOW: {
        unsigned n = word(d);
        if (n == 0 || n > 1024 || n > (d->size - d->pos) / 16) {
            d->failed = true;
            break;
        }
        GskShadow *shadows = g_new(GskShadow, n);
        for (unsigned i = 0; i < n; i++) {
            shadows[i].color = color(d);
            shadows[i].dx = number(d);
            shadows[i].dy = number(d);
            shadows[i].radius = number(d);
            if (shadows[i].radius < 0)
                d->failed = true;
        }
        child = decode_node(d, depth + 1);
        if (child && !d->failed)
            node = gsk_shadow_node_new(child, shadows, n);
        g_free(shadows);
        break;
    }
    case BROADWAY_NODE_OPACITY: {
        float opacity = number(d);
        child = decode_node(d, depth + 1);
        if (opacity < 0 || opacity > 1)
            d->failed = true;
        if (child && !d->failed)
            node = gsk_opacity_node_new(child, opacity);
        break;
    }
    case BROADWAY_NODE_TRANSFORM: {
        unsigned kind = word(d);
        GskTransform *transform = NULL;
        if (kind == 0) {
            float x = number(d), y = number(d);
            graphene_point_t p = GRAPHENE_POINT_INIT(x, y);
            transform = gsk_transform_translate(NULL, &p);
        } else if (kind == 1) {
            float values[16];
            for (unsigned i = 0; i < 16; i++)
                values[i] = number(d);
            graphene_matrix_t matrix;
            graphene_matrix_init_from_float(&matrix, values);
            transform = gsk_transform_matrix(NULL, &matrix);
        } else
            d->failed = true;
        child = decode_node(d, depth + 1);
        if (child && !d->failed)
            node = gsk_transform_node_new(child, transform);
        if (transform)
            gsk_transform_unref(transform);
        break;
    }
    case BROADWAY_NODE_DEBUG: {
        unsigned n = word(d);
        uint64_t padded;
        if (n > 4096 || !align_up_ok(n, 4, &padded) ||
            !window_fits(d->pos, padded, d->size)) {
            d->failed = true;
            break;
        }
        char *message = g_strndup((const char *) d->data + d->pos, n);
        d->pos += padded;
        child = decode_node(d, depth + 1);
        if (child && !d->failed)
            node = gsk_debug_node_new(child, message);
        else
            g_free(message);
        break;
    }
    default:
        d->failed = true;
        break;
    }
    if (child)
        gsk_render_node_unref(child);
    d->children = parent;
    if (!node || d->failed || id == 0) {
        if (node)
            gsk_render_node_unref(node);
        d->failed = true;
        g_array_unref(children);
        return NULL;
    }
    if (type == BROADWAY_NODE_REUSE) {
        g_array_unref(children);
    } else {
        if (g_hash_table_contains(d->next, GUINT_TO_POINTER(id)) ||
            g_hash_table_size(d->next) >= MAX_NODES) {
            gsk_render_node_unref(node);
            g_array_unref(children);
            d->failed = true;
            return NULL;
        }
        SceneNode *entry = g_new(SceneNode, 1);
        *entry = (SceneNode) {1, gsk_render_node_ref(node), children};
        g_hash_table_insert(d->next, GUINT_TO_POINTER(id), entry);
    }
    if (parent)
        g_array_append_val(parent, id);
    return node;
}

static bool send_reply(Client *c,
                       void *data,
                       size_t size,
                       uint32_t type,
                       uint32_t serial)
{
    BroadwayReplyBase *base = data;
    base->size = size;
    base->in_reply_to = serial;
    base->type = type;
    GOutputStream *out =
        g_io_stream_get_output_stream(G_IO_STREAM(c->connection));
    return g_output_stream_write_all(out, data, size, NULL, NULL, NULL);
}

static bool send_event(Client *c, BroadwayInputMsg *event, size_t size)
{
    BroadwayReplyEvent reply;
    memset(&reply, 0, sizeof(reply));
    event->base.serial = c->serial;
    event->base.time = g_get_monotonic_time() / 1000;
    memcpy(&reply.msg, event, size);
    return send_reply(c, &reply,
                      G_STRUCT_OFFSET(BroadwayReplyEvent, msg) + size,
                      BROADWAY_REPLY_EVENT, 0);
}
static gboolean acknowledge_frames(gpointer data)
{
    Surface *s = data;
    s->frame_source = 0;
    while (!g_queue_is_empty(&s->frames)) {
        BroadwayInputMsg *event = g_queue_pop_head(&s->frames);
        send_event(s->client, event, sizeof(event->roundtrip_notify));
        g_free(event);
    }
    return G_SOURCE_REMOVE;
}


static void configure(Surface *s)
{
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_CONFIGURE_NOTIFY;
    event.configure_notify.id = s->id;
    event.configure_notify.x = s->x;
    event.configure_notify.y = s->y;
    event.configure_notify.width = s->width;
    event.configure_notify.height = s->height;
    send_event(s->client, &event, sizeof(event.configure_notify));
}

static void draw(GtkDrawingArea *area,
                 cairo_t *cr,
                 int width,
                 int height,
                 gpointer userdata)
{
    (void) area;
    Surface *s = userdata;
    if (s->root)
        gsk_render_node_draw(s->root, cr);
    if (s->width != width || s->height != height) {
        s->width = width;
        s->height = height;
        configure(s);
    }
}

static void pointer_event(Surface *s,
                          unsigned type,
                          double x,
                          double y,
                          unsigned button,
                          GtkEventController *controller)
{
    Client *c = s->client;
    c->pointer_surface = s->id;
    c->pointer_x = x;
    c->pointer_y = y;
    c->modifiers = gtk_event_controller_get_current_event_state(controller);
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = type;
    event.pointer.mouse_surface_id = s->id;
    event.pointer.event_surface_id = s->id;
    event.pointer.root_x = x + s->x;
    event.pointer.root_y = y + s->y;
    event.pointer.win_x = x;
    event.pointer.win_y = y;
    event.pointer.state = c->modifiers;
    size_t size = sizeof(event.pointer);
    if (type == BROADWAY_EVENT_ENTER || type == BROADWAY_EVENT_LEAVE) {
        event.crossing.mode = 0;
        size = sizeof(event.crossing);
    } else if (type == BROADWAY_EVENT_BUTTON_PRESS ||
               type == BROADWAY_EVENT_BUTTON_RELEASE) {
        event.button.button = button;
        size = sizeof(event.button);
    }
    send_event(c, &event, size);
}

static void motion(GtkEventControllerMotion *controller,
                   double x,
                   double y,
                   gpointer data)
{
    pointer_event(data, BROADWAY_EVENT_POINTER_MOVE, x, y, 0,
                  GTK_EVENT_CONTROLLER(controller));
}

static void enter(GtkEventControllerMotion *controller,
                  double x,
                  double y,
                  gpointer data)
{
    pointer_event(data, BROADWAY_EVENT_ENTER, x, y, 0,
                  GTK_EVENT_CONTROLLER(controller));
}

static void leave(GtkEventControllerMotion *controller, gpointer data)
{
    Surface *s = data;
    pointer_event(s, BROADWAY_EVENT_LEAVE, s->client->pointer_x,
                  s->client->pointer_y, 0, GTK_EVENT_CONTROLLER(controller));
}

static void pressed(GtkGestureClick *gesture,
                    int n,
                    double x,
                    double y,
                    gpointer data)
{
    (void) n;
    Surface *s = data;
    gtk_widget_grab_focus(s->canvas);
    pointer_event(
        s, BROADWAY_EVENT_BUTTON_PRESS, x, y,
        gtk_gesture_single_get_current_button(GTK_GESTURE_SINGLE(gesture)),
        GTK_EVENT_CONTROLLER(gesture));
}

static void released(GtkGestureClick *gesture,
                     int n,
                     double x,
                     double y,
                     gpointer data)
{
    (void) n;
    pointer_event(
        data, BROADWAY_EVENT_BUTTON_RELEASE, x, y,
        gtk_gesture_single_get_current_button(GTK_GESTURE_SINGLE(gesture)),
        GTK_EVENT_CONTROLLER(gesture));
}

static gboolean scroll(GtkEventControllerScroll *controller,
                       double dx,
                       double dy,
                       gpointer data)
{
    (void) dx;
    Surface *s = data;
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_SCROLL;
    event.pointer.event_surface_id = s->id;
    event.pointer.mouse_surface_id = s->id;
    event.pointer.win_x = s->client->pointer_x;
    event.pointer.win_y = s->client->pointer_y;
    event.pointer.root_x = event.pointer.win_x + s->x;
    event.pointer.root_y = event.pointer.win_y + s->y;
    event.pointer.state = gtk_event_controller_get_current_event_state(
        GTK_EVENT_CONTROLLER(controller));
    event.scroll.dir = dy < 0 ? 0 : 1;
    send_event(s->client, &event, sizeof(event.scroll));
    return TRUE;
}

static gboolean key_press(GtkEventControllerKey *controller,
                          guint key,
                          guint code,
                          GdkModifierType state,
                          gpointer data)
{
    (void) controller;
    (void) code;
    Surface *s = data;
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_KEY_PRESS;
    event.key.surface_id = s->id;
    event.key.state = state;
    event.key.key = key;
    send_event(s->client, &event, sizeof(event.key));
    return TRUE;
}

static void key_release(GtkEventControllerKey *controller,
                        guint key,
                        guint code,
                        GdkModifierType state,
                        gpointer data)
{
    (void) controller;
    (void) code;
    Surface *s = data;
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_KEY_RELEASE;
    event.key.surface_id = s->id;
    event.key.state = state;
    event.key.key = key;
    send_event(s->client, &event, sizeof(event.key));
}

static void focus_change(GObject *object, GParamSpec *spec, gpointer data)
{
    (void) spec;
    Surface *s = data;
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_FOCUS;
    if (gtk_window_is_active(GTK_WINDOW(object)))
        event.focus.new_id = s->id;
    else
        event.focus.old_id = s->id;
    send_event(s->client, &event, sizeof(event.focus));
}

static gboolean close_window(GtkWindow *window, gpointer data)
{
    (void) window;
    Surface *s = data;
    if (guest_pid)
        kill(guest_pid, SIGTERM);
    else
        g_io_stream_close(G_IO_STREAM(s->client->connection), NULL, NULL);
    return TRUE;
}

static void free_surface(gpointer data)
{
    Surface *s = data;
    if (s->frame_source)
        g_source_remove(s->frame_source);
    g_queue_clear_full(&s->frames, g_free);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(s->canvas), NULL, NULL,
                                   NULL);
    gtk_window_destroy(s->window);
    if (s->root)
        gsk_render_node_unref(s->root);
    g_hash_table_unref(s->nodes);
    g_free(s);
}

static void free_texture(gpointer data)
{
    g_object_unref(data);
}

static Surface *new_surface(Client *c, BroadwayRequestNewSurface *req)
{
    if (g_hash_table_size(c->surfaces) >= MAX_SURFACES || req->width == 0 ||
        req->height == 0 || req->width > 16384 || req->height > 16384)
        return NULL;
    Surface *s = g_new0(Surface, 1);
    s->client = c;
    s->id = next_surface++;
    s->x = req->x;
    s->y = req->y;
    s->width = req->width;
    s->height = req->height;
    s->window = GTK_WINDOW(gtk_window_new());
    gtk_window_set_title(s->window, "ATL on macOS GTK");
    gtk_window_set_default_size(s->window, s->width, s->height);
    s->canvas = gtk_drawing_area_new();
    gtk_widget_set_focusable(s->canvas, TRUE);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(s->canvas), draw, s, NULL);
    gtk_window_set_child(s->window, s->canvas);
    s->nodes = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                     free_scene_node);
    GtkEventController *ctrl = gtk_event_controller_motion_new();
    g_signal_connect(ctrl, "motion", G_CALLBACK(motion), s);
    g_signal_connect(ctrl, "enter", G_CALLBACK(enter), s);
    g_signal_connect(ctrl, "leave", G_CALLBACK(leave), s);
    gtk_widget_add_controller(s->canvas, ctrl);
    GtkGesture *gesture = gtk_gesture_click_new();
    gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture), 0);
    g_signal_connect(gesture, "pressed", G_CALLBACK(pressed), s);
    g_signal_connect(gesture, "released", G_CALLBACK(released), s);
    gtk_widget_add_controller(s->canvas, GTK_EVENT_CONTROLLER(gesture));
    ctrl =
        gtk_event_controller_scroll_new(GTK_EVENT_CONTROLLER_SCROLL_BOTH_AXES);
    g_signal_connect(ctrl, "scroll", G_CALLBACK(scroll), s);
    gtk_widget_add_controller(s->canvas, ctrl);
    ctrl = gtk_event_controller_key_new();
    g_signal_connect(ctrl, "key-pressed", G_CALLBACK(key_press), s);
    g_signal_connect(ctrl, "key-released", G_CALLBACK(key_release), s);
    gtk_widget_add_controller(s->canvas, ctrl);
    g_signal_connect(s->window, "notify::is-active", G_CALLBACK(focus_change),
                     s);
    g_signal_connect(s->window, "close-request", G_CALLBACK(close_window), s);
    g_hash_table_insert(c->surfaces, GUINT_TO_POINTER(s->id), s);
    return s;
}

static bool request(Client *c, BroadwayRequest *req)
{
    BroadwayReply reply;
    memset(&reply, 0, sizeof(reply));
    uint32_t serial = req->base.serial;
    c->serial = serial;
    Surface *s = NULL;
    if (req->base.size >= sizeof(BroadwayRequestDestroySurface))
        s = g_hash_table_lookup(c->surfaces,
                                GUINT_TO_POINTER(req->destroy_surface.id));
#define NEED(member)                               \
    do {                                           \
        if (req->base.size != sizeof(req->member)) \
            return false;                          \
    } while (0)
    switch (req->base.type) {
    case BROADWAY_REQUEST_NEW_SURFACE:
        NEED(new_surface);
        s = new_surface(c, &req->new_surface);
        if (!s)
            return false;
        reply.new_surface.id = s->id;
        return send_reply(c, &reply, sizeof(reply.new_surface),
                          BROADWAY_REPLY_NEW_SURFACE, serial);
    case BROADWAY_REQUEST_SYNC:
        NEED(sync);
        return send_reply(c, &reply, sizeof(reply.sync), BROADWAY_REPLY_SYNC,
                          serial);
    case BROADWAY_REQUEST_FLUSH:
        NEED(flush);
        break;
    case BROADWAY_REQUEST_QUERY_MOUSE:
        NEED(query_mouse);
        reply.query_mouse.surface = c->pointer_surface;
        reply.query_mouse.root_x = c->pointer_x;
        reply.query_mouse.root_y = c->pointer_y;
        Surface *pointer = g_hash_table_lookup(
            c->surfaces, GUINT_TO_POINTER(c->pointer_surface));
        if (pointer) {
            reply.query_mouse.root_x += pointer->x;
            reply.query_mouse.root_y += pointer->y;
        }
        reply.query_mouse.mask = c->modifiers;
        return send_reply(c, &reply, sizeof(reply.query_mouse),
                          BROADWAY_REPLY_QUERY_MOUSE, serial);
    case BROADWAY_REQUEST_SHOW_SURFACE:
        NEED(show_surface);
        if (!s)
            return false;
        gtk_window_present(s->window);
        configure(s);
        break;
    case BROADWAY_REQUEST_HIDE_SURFACE:
        NEED(hide_surface);
        if (!s)
            return false;
        gtk_widget_set_visible(GTK_WIDGET(s->window), FALSE);
        break;
    case BROADWAY_REQUEST_DESTROY_SURFACE:
        NEED(destroy_surface);
        if (!s)
            return false;
        g_hash_table_remove(c->surfaces, GUINT_TO_POINTER(s->id));
        break;
    case BROADWAY_REQUEST_MOVE_RESIZE:
        NEED(move_resize);
        if (!s || !req->move_resize.width || !req->move_resize.height ||
            req->move_resize.width > 16384 || req->move_resize.height > 16384)
            return false;
        if (req->move_resize.with_move) {
            s->x = req->move_resize.x;
            s->y = req->move_resize.y;
        }
        s->width = req->move_resize.width;
        s->height = req->move_resize.height;
        gtk_window_set_default_size(s->window, s->width, s->height);
        configure(s);
        break;
    case BROADWAY_REQUEST_SET_TRANSIENT_FOR: {
        NEED(set_transient_for);
        if (!s)
            return false;
        Surface *parent = g_hash_table_lookup(
            c->surfaces, GUINT_TO_POINTER(req->set_transient_for.parent));
        gtk_window_set_transient_for(s->window, parent ? parent->window : NULL);
        break;
    }
    case BROADWAY_REQUEST_SET_MODAL_HINT:
        NEED(set_modal_hint);
        if (!s)
            return false;
        gtk_window_set_modal(s->window, req->set_modal_hint.modal_hint);
        break;
    case BROADWAY_REQUEST_FOCUS_SURFACE:
        NEED(focus_surface);
        if (!s)
            return false;
        gtk_window_present(s->window);
        gtk_widget_grab_focus(s->canvas);
        break;
    case BROADWAY_REQUEST_ROUNDTRIP: {
        NEED(roundtrip);
        if (!s)
            return false;
        if (g_queue_get_length(&s->frames) >= 128)
            return false;
        BroadwayInputMsg *event = g_new0(BroadwayInputMsg, 1);
        event->base.type = BROADWAY_EVENT_ROUNDTRIP_NOTIFY;
        event->roundtrip_notify.id = s->id;
        event->roundtrip_notify.tag = req->roundtrip.tag;
        g_queue_push_tail(&s->frames, event);
        if (!s->frame_source)
            s->frame_source = g_timeout_add(33, acknowledge_frames, s);
        break;
    }
    case BROADWAY_REQUEST_GRAB_POINTER:
        NEED(grab_pointer);
        if (!s)
            return false;
        reply.grab_pointer.status = 0;
        return send_reply(c, &reply, sizeof(reply.grab_pointer),
                          BROADWAY_REPLY_GRAB_POINTER, serial);
    case BROADWAY_REQUEST_UNGRAB_POINTER:
        NEED(ungrab_pointer);
        reply.ungrab_pointer.status = 0;
        return send_reply(c, &reply, sizeof(reply.ungrab_pointer),
                          BROADWAY_REPLY_UNGRAB_POINTER, serial);
    case BROADWAY_REQUEST_SET_SHOW_KEYBOARD:
        NEED(set_show_keyboard);
        break;
    case BROADWAY_REQUEST_UPLOAD_TEXTURE: {
        NEED(upload_texture);
        if (g_queue_is_empty(&c->fds) || req->upload_texture.size < 33 ||
            req->upload_texture.size > MAX_TEXTURE)
            return false;
        int fd = GPOINTER_TO_INT(g_queue_pop_head(&c->fds));
        size_t size = req->upload_texture.size;
        uint8_t *data = g_malloc(size);
        size_t copied = 0;
        while (copied < size) {
            ssize_t n = pread(fd, data + copied, size - copied,
                              (off_t) req->upload_texture.offset + copied);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            copied += n;
        }
        close(fd);
        if (copied != size) {
            g_free(data);
            return false;
        }
        if (memcmp(data, "\211PNG\r\n\032\n", 8) || png_word(data + 8) != 13 ||
            memcmp(data + 12, "IHDR", 4)) {
            g_free(data);
            return false;
        }
        uint32_t width = png_word(data + 16), height = png_word(data + 20);
        uint64_t decoded = (uint64_t) width * height * 8;
        if (!width || !height || width > 16384 || height > 16384 ||
            decoded > MAX_TEXTURE ||
            c->texture_budget->bytes > MAX_TEXTURE_TOTAL - decoded) {
            g_free(data);
            return false;
        }
        GBytes *bytes = g_bytes_new_take(data, size);
        GError *error = NULL;
        GdkTexture *texture = gdk_texture_new_from_bytes(bytes, &error);
        g_bytes_unref(bytes);
        if (!texture) {
            g_clear_error(&error);
            return false;
        }
        if (gdk_texture_get_width(texture) > 16384 ||
            gdk_texture_get_height(texture) > 16384) {
            g_object_unref(texture);
            return false;
        }
        Texture *t = g_new(Texture, 1);
        *t = (Texture) {decoded, c->texture_budget};
        c->texture_budget->refs++;
        c->texture_budget->bytes += decoded;
        g_object_set_data_full(G_OBJECT(texture), "texture-budget", t,
                               release_texture_budget);
        g_hash_table_replace(c->textures,
                             GUINT_TO_POINTER(req->upload_texture.id), texture);
        break;
    }
    case BROADWAY_REQUEST_RELEASE_TEXTURE: {
        NEED(release_texture);
        g_hash_table_remove(c->textures,
                            GUINT_TO_POINTER(req->release_texture.id));
        break;
    }
    case BROADWAY_REQUEST_SET_NODES: {
        if (!s || req->base.size < 24 || req->base.size % 4)
            return false;
        GHashTable *next = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                 NULL, free_scene_node);
        Decoder d = {.data = (const uint8_t *) req + 16,
                     .size = req->base.size - 16,
                     .surface = s,
                     .next = next};
        GskRenderNode *root = decode_node(&d, 0);
        if (!root || d.failed || d.pos != d.size) {
            if (root)
                gsk_render_node_unref(root);
            g_hash_table_unref(next);
            return false;
        }
        if (s->root)
            gsk_render_node_unref(s->root);
        s->root = root;
        g_hash_table_unref(s->nodes);
        s->nodes = next;
        gtk_widget_queue_draw(s->canvas);
        break;
    }
    default:
        return false;
    }
#undef NEED
    return true;
}

static void disconnect_client(Client *c)
{
    g_source_destroy(c->source);
    clients = g_list_remove(clients, c);
    g_hash_table_unref(c->surfaces);
    g_hash_table_unref(c->textures);
    if (--c->texture_budget->refs == 0)
        g_free(c->texture_budget);
    while (!g_queue_is_empty(&c->fds))
        close(GPOINTER_TO_INT(g_queue_pop_head(&c->fds)));
    g_io_stream_close(G_IO_STREAM(c->connection), NULL, NULL);
    g_object_unref(c->connection);
    g_byte_array_unref(c->buffer);
    g_source_unref(c->source);
    g_free(c);
}

static gboolean input(GPollableInputStream *stream, gpointer data)
{
    (void) stream;
    Client *c = data;
    uint8_t bytes[65536];
    GInputVector vector = {bytes, sizeof(bytes)};
    GSocketControlMessage **messages = NULL;
    int nmessages = 0;
    GError *error = NULL;
    GSocket *socket = g_socket_connection_get_socket(c->connection);
    gssize n = g_socket_receive_message(socket, NULL, &vector, 1, &messages,
                                        &nmessages, NULL, NULL, &error);
    if (n < 0 && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
        g_clear_error(&error);
        return G_SOURCE_CONTINUE;
    }
    bool valid = n > 0;
    for (int i = 0; i < nmessages; i++) {
        if (G_IS_UNIX_FD_MESSAGE(messages[i])) {
            int count;
            int *fds = g_unix_fd_message_steal_fds(
                G_UNIX_FD_MESSAGE(messages[i]), &count);
            for (int j = 0; j < count; j++) {
                if (g_queue_get_length(&c->fds) < 128)
                    g_queue_push_tail(&c->fds, GINT_TO_POINTER(fds[j]));
                else {
                    close(fds[j]);
                    valid = false;
                }
            }
            g_free(fds);
        }
        g_object_unref(messages[i]);
    }
    g_free(messages);
    g_clear_error(&error);
    if (valid && (size_t) n <= MAX_MESSAGE - c->buffer->len)
        g_byte_array_append(c->buffer, bytes, n);
    else
        valid = false;
    size_t consumed = 0;
    while (valid && c->buffer->len - consumed >= 12) {
        uint32_t size;
        memcpy(&size, c->buffer->data + consumed, 4);
        if (size < 12 || size > MAX_MESSAGE || size % 4) {
            valid = false;
            break;
        }
        if (size > c->buffer->len - consumed)
            break;
        valid = request(c, (BroadwayRequest *) (c->buffer->data + consumed));
        consumed += size;
    }
    if (!valid) {
        if (n > 0)
            g_printerr("GTK bridge: invalid surface request\n");
        disconnect_client(c);
        return G_SOURCE_REMOVE;
    }
    g_byte_array_remove_range(c->buffer, 0, consumed);
    return G_SOURCE_CONTINUE;
}

static gboolean incoming(GSocketService *service,
                         GSocketConnection *connection,
                         GObject *source,
                         gpointer data)
{
    (void) service;
    (void) source;
    (void) data;
    if (g_list_length(clients) >= 16)
        return FALSE;
    Client *c = g_new0(Client, 1);
    c->connection = g_object_ref(connection);
    c->buffer = g_byte_array_new();
    c->texture_budget = g_new0(TextureBudget, 1);
    c->texture_budget->refs = 1;
    c->textures = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                        free_texture);
    c->surfaces = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                        free_surface);
    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    c->source = g_pollable_input_stream_create_source(
        G_POLLABLE_INPUT_STREAM(in), NULL);
    g_source_set_callback(c->source, G_SOURCE_FUNC(input), c, NULL);
    g_source_attach(c->source, NULL);
    clients = g_list_prepend(clients, c);
    BroadwayInputMsg event;
    memset(&event, 0, sizeof(event));
    event.base.type = BROADWAY_EVENT_SCREEN_SIZE_CHANGED;
    GListModel *monitors = gdk_display_get_monitors(gdk_display_get_default());
    GdkMonitor *monitor = g_list_model_get_item(monitors, 0);
    GdkRectangle geometry = {0, 0, 1280, 800};
    if (monitor) {
        gdk_monitor_get_geometry(monitor, &geometry);
        g_object_unref(monitor);
    }
    event.screen_resize_notify.width = geometry.width;
    event.screen_resize_notify.height = geometry.height;
    event.screen_resize_notify.scale = 1;
    send_event(c, &event, sizeof(event.screen_resize_notify));
    return TRUE;
}

static void child_exit(GPid pid, int status, gpointer data)
{
    (void) data;
    guest_status =
        WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    guest_pid = 0;
    g_spawn_close_pid(pid);
    g_main_loop_quit(loop);
}

static gboolean stop_bridge(gpointer data)
{
    (void) data;
    if (guest_pid)
        kill(guest_pid, SIGTERM);
    else
        g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: elfuse-gtk [--listen DIRECTORY | ELFUSE ARG...]\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    g_set_prgname("elfuse-gtk");
    g_setenv("GDK_BACKEND", "macos", TRUE);
    gtk_init();
    GError *error = NULL;
    bool listen_only = strcmp(argv[1], "--listen") == 0;
    if (listen_only) {
        if (argc != 3)
            return 1;
        runtime_dir = g_strdup(argv[2]);
        if (g_mkdir_with_parents(runtime_dir, 0700) < 0)
            return 1;
    } else {
        char path[] = "/private/tmp/elfuse-gtk-XXXXXX";
        if (!mkdtemp(path)) {
            perror("mkdtemp");
            return 1;
        }
        runtime_dir = g_strdup(path);
    }
    socket_path = g_build_filename(runtime_dir, "broadway1.socket", NULL);
    GSocketService *service = g_socket_service_new();
    GSocketAddress *address = g_unix_socket_address_new(socket_path);
    if (!g_socket_listener_add_address(
            G_SOCKET_LISTENER(service), address, G_SOCKET_TYPE_STREAM,
            G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, &error)) {
        fprintf(stderr, "GTK bridge: %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    g_object_unref(address);
    chmod(socket_path, 0600);
    g_signal_connect(service, "incoming", G_CALLBACK(incoming), NULL);
    g_socket_service_start(service);
    loop = g_main_loop_new(NULL, FALSE);
    if (!listen_only) {
        char **env = g_get_environ();
        env = g_environ_setenv(env, "GDK_BACKEND", "broadway", TRUE);
        env = g_environ_setenv(env, "GSK_RENDERER", "broadway", TRUE);
        env = g_environ_setenv(env, "BROADWAY_DISPLAY", ":0", TRUE);
        env = g_environ_setenv(env, "XDG_RUNTIME_DIR", runtime_dir, TRUE);
        if (!g_spawn_async(NULL, argv + 1, env,
                           G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                           NULL, NULL, &guest_pid, &error)) {
            fprintf(stderr, "GTK bridge: %s\n", error->message);
            g_clear_error(&error);
            guest_status = 1;
        }
        g_strfreev(env);
        if (guest_pid)
            g_child_watch_add(guest_pid, child_exit, NULL);
    }
    g_unix_signal_add(SIGTERM, stop_bridge, NULL);
    g_unix_signal_add(SIGINT, stop_bridge, NULL);
    printf("GTK_NATIVE_READY %s\n", socket_path);
    fflush(stdout);
    if (listen_only || guest_pid)
        g_main_loop_run(loop);
    g_socket_service_stop(service);
    while (clients)
        disconnect_client(clients->data);
    g_object_unref(service);
    g_main_loop_unref(loop);
    unlink(socket_path);
    if (!listen_only)
        rmdir(runtime_dir);
    g_free(socket_path);
    g_free(runtime_dir);
    return guest_status;
}
