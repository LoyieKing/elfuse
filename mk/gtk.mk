# Optional native GTK presentation, separate from the HVF executable.

.PHONY: elfuse-gtk
## Build the native macOS GTK surface bridge (requires gtk4 and pkg-config)
elfuse-gtk: $(BUILD_DIR)/elfuse-gtk

$(BUILD_DIR)/elfuse-gtk: src/gtk/gtk-native.c src/gtk/native-protocol.h \
                       src/proved/align.h | $(BUILD_DIR)
	@command -v pkg-config >/dev/null || { echo 'Install pkg-config and gtk4'; exit 1; }
	@pkg-config --atleast-version=4.24 gtk4 && pkg-config --exists gio-unix-2.0 || { echo 'GTK 4.24 and gio-unix-2.0 are required'; exit 1; }
	@echo "  CC      $@"
	$(Q)$(CC) -Isrc -O2 -Wall -Wextra -Werror \
		$$(pkg-config --cflags gtk4 gio-unix-2.0) -o $@ $< \
		$$(pkg-config --libs gtk4 gio-unix-2.0)

.PHONY: test-gtk-native-host
## Check native GTK scene reuse and malformed input boundaries
test-gtk-native-host: $(BUILD_DIR)/test-gtk-native-host
	$(Q)$<

$(BUILD_DIR)/test-gtk-native-host: tests/test-gtk-native-host.c \
        tests/host-test-util.h src/gtk/gtk-native.c src/gtk/native-protocol.h \
        src/proved/align.h | $(BUILD_DIR)
	@pkg-config --atleast-version=4.24 gtk4 && pkg-config --exists gio-unix-2.0
	$(Q)$(CC) -Isrc -O2 -Wall -Wextra -Werror \
		$$(pkg-config --cflags gtk4 gio-unix-2.0) -o $@ $< \
		$$(pkg-config --libs gtk4 gio-unix-2.0)
