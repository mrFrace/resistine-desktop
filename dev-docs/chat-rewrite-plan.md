# Chat UI Rewrite: Per-Bubble Frames in CTkScrollableFrame

  ## Context

  The current chat plugin (`plugins/chat/`) is built on a single `CTkTextbox` that holds every message as a `window_create` embed. Assistant messages use
  a 1069-line `MarkdownBubble` class that hand-rolls a markdown parser, configures Tk text tags via the private `_textbox`, and embeds
  `tk.Frame`/`tk.Text`/`CairoCanvas` widgets via `window_create` for code blocks, tables, and horizontal rules. Over time, patching this architecture has
  caused new bugs for every fix (the 30-commit chat history in `git log` tells the story).

  The two visible symptoms in the latest screenshots are:

  1. **Bold text renders visibly oversized** inside paragraphs and lists. Root cause: `CTkTextbox.tag_config(font=...)` is explicitly forbidden by
  CustomTkinter because it breaks scaling, so the current code reaches into `_textbox` and bypasses CTk's DPI/scale handling. Bold tags therefore render
  at literal pt while the base font renders at scaled pt. Commit `902cd2b` tried to fix this by raising heading tags over bold and switching all tag fonts
   to `CTkFont`, but the fix is brittle — inline bold inside tables/lists still hits the same class of bug because tag cascade in Tk picks one font
  wholesale, it doesn't merge weight-from-bold with size-from-parent.
  2. **Spacing is inconsistent** across bold lines, list items, and bullet indentation. Root cause: `spacing1`/`spacing3` are per-tag, so overlapping tags
   double/triple the spacing unpredictably.

  The intended outcome of this rewrite: replace the architecture underneath the chat screen with a **per-bubble `CTkFrame` model inside a
  `CTkScrollableFrame`**, using **`tk.Text` (not `CTkTextbox`) with named `tkFont.Font` objects** for rich content inside each assistant bubble. This
  pattern is already used by `plugins/help/`, `plugins/dashboard/`, `plugins/settings/` so the chat plugin stops being the outlier. It eliminates the
  `window_create` layer entirely, which in turn deletes most of the platform-specific scroll-redirect glue.

  ---

  ## Approach

  ### Architecture (new)

  ```
  second_frame (CTkFrame, grid row=0)
  ├── chat_scroll (CTkScrollableFrame)  ← replaces CTkTextbox
  │   ├── welcome_frame (CTkFrame, shown when no history)
  │   ├── BubbleRow (CTkFrame, fill="x") ───┐
  │   │   └── UserBubble (CTkFrame, pack side="right")      │
  │   │       └── CTkLabel (wraplength, Inter 15)           │  repeated
  │   └── BubbleRow (CTkFrame, fill="x")                    │  per message
  │       └── AssistantBubble (CTkFrame, pack side="left")  │
  │           └── MarkdownRenderer output:                  │
  │               ├── tk.Text (paragraphs, inline rich)     │
  │               ├── CodeBlockWidget (separate CTkFrame)   │
  │               ├── TableWidget (separate CTkFrame)       │
  │               └── HorizontalRuleWidget                  ─┘
  └── input_bar (placed at bottom via .place())   — UNCHANGED
      ├── chat_entry (EmojiEntry)
      └── send_button
  ```

  ### Key design decisions

  1. **One `tk.Text` per assistant bubble, not `CTkTextbox`.** Using raw `tk.Text` means `tag_config(font=...)` works normally — no monkey-patching, no
  scaling workaround. We restyle fonts/colors manually to match the CTk theme. Each bubble's `Text` only holds its own content, so tag state can never
  leak across messages.

  2. **Named `tkFont.Font` objects**, created once in `plugins/chat/fonts.py`, all derived from the same base size. Every `tag_configure` call references
  a named font by name. This is the canonical fix for the "oversized bold" bug class and kills it permanently.

  3. **No more `window_create`.** Code blocks, tables, and horizontal rules become normal sibling `CTkFrame` widgets inside the bubble, packed in order.
  When a markdown block switches between prose and a code block, we close the current `tk.Text`, pack a `CodeBlockWidget`, then open a new `tk.Text` for
  the next prose block. This keeps each `tk.Text` simple (no embedded windows) and eliminates the entire scroll-redirect subsystem inside
  `MarkdownBubble`.

  4. **`CTkScrollableFrame` handles scrolling natively.** Delete `_bind_mousewheel`, `_bind_scroll_redirect_to_chat`, `_init_scroll_redirect`,
  `_bind_scroll_redirect`, and the shared-velocity state. `CTkScrollableFrame` already gives mouse-wheel + trackpad scrolling on all three platforms (Help
   plugin proves this works with embedded `MarkdownBubble`s). The `utils/scroll.py` constants stay in place since `utils/scroll.py` is also used for
  non-chat scrolling — verify before touching.

  5. **Streaming model: plain text → swap to markdown on completion.** During stream, the assistant bubble's content is a plain-text `tk.Label`/`Text`
  showing the raw token stream as it arrives. On stream end, we destroy that placeholder and replace it with the full `MarkdownRenderer` output. This:
     - Eliminates the "bold appears then unbolds" visual glitch when `**` tokens arrive incrementally.
     - Eliminates the per-token reparse cost.
     - Eliminates flicker from `window_create` relayout during streaming.
     - Matches what ChatGPT/Claude desktop clients do.
     The 50ms polling loop + queue stays — it works.

  6. **Preserve `MarkdownBubble` public API** for the Help plugin and `emoji_entry.py`:
     - `MarkdownBubble(master, markdown_content, **kwargs)` constructor signature stays identical.
     - Static methods `MarkdownBubble._render_emoji(emoji, size)` and `MarkdownBubble._split_emoji_chars(text)` stay on the class.
     - Internally, `MarkdownBubble.__init__` delegates to the new `MarkdownRenderer` which builds the per-widget tree into `self`.

  7. **Bubble width handling.** Bind `<Configure>` on `chat_scroll` and recompute `wraplength` for all bubbles. Cap assistant bubbles at ~72% of scroll
  frame width, max 900px for readability. User bubbles at ~75% of scroll frame width, max 600px (matches current). Floor of 200px so we never wrap
  single-word-per-line.

  8. **Auto-scroll-to-bottom only when already at bottom.** Check `chat_scroll._parent_canvas.yview()[1] > 0.95` before new bubble insert. If the user
  scrolled up to read history, don't yank them back.

  9. **File structure** (respecting global CLAUDE.md's 300-line cap per file):

     | File | Purpose | Approx LOC |
     |---|---|---|
     | `plugins/chat/main.py` | Plugin class, screen build, streaming controller, input bar | ~300 |
     | `plugins/chat/fonts.py` | Named `tkFont.Font` registry, theme-aware | ~80 |
     | `plugins/chat/bubble.py` | `UserBubble`, `AssistantBubble`, `BubbleRow` widget classes | ~250 |
     | `plugins/chat/markdown_renderer.py` | `MarkdownRenderer`: parses markdown, packs widgets into a parent | ~300 |
     | `plugins/chat/markdown_widgets.py` | `CodeBlockWidget`, `TableWidget`, `HorizontalRule` classes | ~250 |
     | `plugins/chat/markdown_bubble.py` | **Thin shim**: `MarkdownBubble` extends `CTkFrame`, creates a `MarkdownRenderer` in itself, keeps static emoji
  methods. Preserves public API for Help + emoji_entry. | ~180 |
     | `plugins/chat/streaming.py` | Stream worker thread + queue poller | ~150 |
     | `plugins/chat/welcome_scre
  ⎿  Interrupted · What should Claude do instead?

❯ /plan
  ⎿  Current Plan
     /Users/dhahabwhbbjshehaha/.claude/plans/peaceful-meandering-hinton.md

     Chat UI Rewrite: Per-Bubble Frames in CTkScrollableFrame

     Context

     The current chat plugin (plugins/chat/) is built on a single CTkTextbox that
      holds every message as a window_create embed. Assistant messages use a
     1069-line MarkdownBubble class that hand-rolls a markdown parser, configures
     Tk text tags via the private _textbox, and embeds
     tk.Frame/tk.Text/CairoCanvas widgets via window_create for code blocks,
     tables, and horizontal rules. Over time, patching this architecture has caused
     new bugs for every fix (the 30-commit chat history in git log tells the
     story).

     The two visible symptoms in the latest screenshots are:

     1. Bold text renders visibly oversized inside paragraphs and lists. Root
     cause: CTkTextbox.tag_config(font=...) is explicitly forbidden by
     CustomTkinter because it breaks scaling, so the current code reaches into
     _textbox and bypasses CTk's DPI/scale handling. Bold tags therefore render at
     literal pt while the base font renders at scaled pt. Commit 902cd2b tried to
     fix this by raising heading tags over bold and switching all tag fonts to
     CTkFont, but the fix is brittle — inline bold inside tables/lists still hits
     the same class of bug because tag cascade in Tk picks one font wholesale, it
     doesn't merge weight-from-bold with size-from-parent.
     2. Spacing is inconsistent across bold lines, list items, and bullet
     indentation. Root cause: spacing1/spacing3 are per-tag, so overlapping tags
     double/triple the spacing unpredictably.

     The intended outcome of this rewrite: replace the architecture underneath the
     chat screen with a per-bubble CTkFrame model inside a
     CTkScrollableFrame, using tk.Text (not CTkTextbox) with named
     tkFont.Font objects for rich content inside each assistant bubble. This
     pattern is already used by plugins/help/, plugins/dashboard/,
     plugins/settings/ so the chat plugin stops being the outlier. It eliminates
     the window_create layer entirely, which in turn deletes most of the
     platform-specific scroll-redirect glue.

     ---
     Approach

     Architecture (new)

     second_frame (CTkFrame, grid row=0)
     ├── chat_scroll (CTkScrollableFrame)  ← replaces CTkTextbox
     │   ├── welcome_frame (CTkFrame, shown when no history)
     │   ├── BubbleRow (CTkFrame, fill="x") ───┐
     │   │   └── UserBubble (CTkFrame, pack side="right")      │
     │   │       └── CTkLabel (wraplength, Inter 15)           │  repeated
     │   └── BubbleRow (CTkFrame, fill="x")                    │  per message
     │       └── AssistantBubble (CTkFrame, pack side="left")  │
     │           └── MarkdownRenderer output:                  │
     │               ├── tk.Text (paragraphs, inline rich)     │
     │               ├── CodeBlockWidget (separate CTkFrame)   │
     │               ├── TableWidget (separate CTkFrame)       │
     │               └── HorizontalRuleWidget                  ─┘
     └── input_bar (placed at bottom via .place())   — UNCHANGED
         ├── chat_entry (EmojiEntry)
         └── send_button

     Key design decisions

     1. One tk.Text per assistant bubble, not CTkTextbox. Using raw tk.Text
      means tag_config(font=...) works normally — no monkey-patching, no scaling
     workaround. We restyle fonts/colors manually to match the CTk theme. Each
     bubble's Text only holds its own content, so tag state can never leak across
     messages.
     2. Named tkFont.Font objects, created once in plugins/chat/fonts.py, all
      derived from the same base size. Every tag_configure call references a named
     font by name. This is the canonical fix for the "oversized bold" bug class and
     kills it permanently.
     3. No more window_create. Code blocks, tables, and horizontal rules become
      normal sibling CTkFrame widgets inside the bubble, packed in order. When a
     markdown block switches between prose and a code block, we close the current
     tk.Text, pack a CodeBlockWidget, then open a new tk.Text for the next
     prose block. This keeps each tk.Text simple (no embedded windows) and
     eliminates the entire scroll-redirect subsystem inside MarkdownBubble.
     4. CTkScrollableFrame handles scrolling natively. Delete
     _bind_mousewheel, _bind_scroll_redirect_to_chat, _init_scroll_redirect,
     _bind_scroll_redirect, and the shared-velocity state. CTkScrollableFrame
     already gives mouse-wheel + trackpad scrolling on all three platforms (Help
     plugin proves this works with embedded MarkdownBubbles). The utils/scroll.py
      constants stay in place since utils/scroll.py is also used for non-chat
     scrolling — verify before touching.
     5. Streaming model: plain text → swap to markdown on completion. During
     stream, the assistant bubble's content is a plain-text tk.Label/Text showing
      the raw token stream as it arrives. On stream end, we destroy that placeholder
     and replace it with the full MarkdownRenderer output. This:
       - Eliminates the "bold appears then unbolds" visual glitch when ** tokens
     arrive incrementally.
       - Eliminates the per-token reparse cost.
       - Eliminates flicker from window_create relayout during streaming.
       - Matches what ChatGPT/Claude desktop clients do.
     The 50ms polling loop + queue stays — it works.
     6. Preserve MarkdownBubble public API for the Help plugin and
     emoji_entry.py:
       - MarkdownBubble(master, markdown_content, **kwargs) constructor signature
     stays identical.
       - Static methods MarkdownBubble._render_emoji(emoji, size) and
     MarkdownBubble._split_emoji_chars(text) stay on the class.
       - Internally, MarkdownBubble.__init__ delegates to the new
     MarkdownRenderer which builds the per-widget tree into self.
     7. Bubble width handling. Bind <Configure> on chat_scroll and recompute
     wraplength for all bubbles. Cap assistant bubbles at ~72% of scroll frame
     width, max 900px for readability. User bubbles at ~75% of scroll frame width,
     max 600px (matches current). Floor of 200px so we never wrap
     single-word-per-line.
     8. Auto-scroll-to-bottom only when already at bottom. Check
     chat_scroll._parent_canvas.yview()[1] > 0.95 before new bubble insert. If the
     user scrolled up to read history, don't yank them back.
     9. File structure (respecting global CLAUDE.md's 300-line cap per file):

     | File                 | Purpose                                           | Approx LOC |
     |----------------------|---------------------------------------------------|------------|
     | plugins/chat/main.py | Plugin class, screen build, streaming controller, |            |

     input bar | ~300 |
        | plugins/chat/fonts.py | Named tkFont.Font registry, theme-aware | ~80 |
        | plugins/chat/bubble.py | UserBubble, AssistantBubble, BubbleRow
     widget classes | ~250 |
        | plugins/chat/markdown_renderer.py | MarkdownRenderer: parses markdown,
     packs widgets into a parent | ~300 |
        | plugins/chat/markdown_widgets.py | CodeBlockWidget, TableWidget,
     HorizontalRule classes | ~250 |
        | plugins/chat/markdown_bubble.py | Thin shim: MarkdownBubble extends
      CTkFrame, creates a MarkdownRenderer in itself, keeps static emoji methods.
      Preserves public API for Help + emoji_entry. | ~180 |
        | plugins/chat/streaming.py | Stream worker thread + queue poller | ~150 |
        | plugins/chat/welcome_screen.py | Welcome + suggestion chips + API key
     missing screen | ~140 |
        | plugins/chat/animated_text.py | DELETE — dead code, never invoked | —
      |
        | plugins/chat/chat_dark.css | DELETE — dead code, no loader | — |
        | plugins/chat/chat_light.css | DELETE — dead code, no loader | — |

     10. Parsing: keep the existing hand-rolled regex parser (it's not what's
     broken — the rendering layer is). The parser lives in markdown_renderer.py and
      walks lines, emitting calls into a widget-building API (add_paragraph(text),
     add_heading(level, text), add_code_block(lines, lang), add_table(rows),
     add_bullet(text, level), add_hr(), etc.). This is simpler than introducing
     markdown-it-py as a new dependency and lets us port edge cases (box-drawing
     art, admonitions, GFM tables) incrementally.
     11. Out of scope for this rewrite (explicit non-goals):
       - Syntax highlighting via Pygments. Pygments is imported but unused today;
     the rewrite keeps it unused. Future work.
       - Chat history persistence. Current in-memory model stays.
       - Replacing markdown-it-py for the parser. Keep hand-rolled regex.
       - Changing the OpenAI/streaming API.
       - The welcome screen redesign.
       - Adding tests for visual rendering (the existing unit-level tests for API
     behavior stay).

     ---
     Critical files to modify

     - plugins/chat/main.py — full rewrite. ~1200 lines → ~300.
     - plugins/chat/markdown_bubble.py — shim. ~1069 lines → ~180.
     - plugins/chat/animated_text.py — delete (and delete
     tests/unit/test_animated_text.py).
     - plugins/chat/chat_dark.css — delete.
     - plugins/chat/chat_light.css — delete.
     - plugins/chat/fonts.py — new file.
     - plugins/chat/bubble.py — new file.
     - plugins/chat/markdown_renderer.py — new file.
     - plugins/chat/markdown_widgets.py — new file.
     - plugins/chat/streaming.py — new file.
     - plugins/chat/welcome_screen.py — new file.
     - tests/unit/test_animated_text.py — delete (module gone).
     - tests/unit/test_markdown_bubble.py — verify static-method tests still work;
     no other changes expected.
     - tests/unit/test_chat_plugin.py — should pass unchanged; Plugin class
     public API is preserved.

     Files NOT to modify

     - plugins/help/markdown_viewer.py — imports MarkdownBubble; public API
     preserved → no change.
     - utils/emoji_entry.py — imports _EMOJI_RE, _EMOJI_RENDER,
     MarkdownBubble._render_emoji, MarkdownBubble._split_emoji_chars → static
     methods preserved on MarkdownBubble shim.
     - utils/cairo_canvas.py — still used by Linux emoji rendering in the shim.
     - utils/scroll.py — verify no non-chat use before deleting; safest is to leave
      it untouched this pass.
     - utils/settings.py, utils/logger.py — untouched.
     - plugins/base_plugin.py — untouched.

     Existing functions/utilities to reuse

     - customtkinter.CTkScrollableFrame — main container. Already used by
     plugins/help/main.py:67-71, plugins/dashboard/main.py:70-74,
     plugins/settings/main.py:93-97.
     - customtkinter.ThemeManager.theme.get("Theme", {}).get(key) — for
     corner_radius, divider_color.
     - utils.settings.get, get_secret — config access, unchanged.
     - utils.logger.logger — unchanged.
     - utils.emoji_entry.EmojiEntry — input widget, unchanged.
     - self.app.show_notification(msg, type="error") — notification hook
     (gui/user_interface.py:1000).
     - Current _INLINE_RE regex and _insert_inline logic from
     markdown_bubble.py — port into markdown_renderer.py as-is, it parses fine.
     - Current _is_box_drawing, _strip_inline_md, _BOX_CHARS — port as-is
     (existing unit tests depend on them).
     - Current _render_emoji, _split_emoji_chars, _emoji_cache logic — port
     into the shim class unchanged.
     - Current _is_dark_mode, _theme_color logic — port into fonts.py and
     bubble.py.
     - Current 50ms polling + queue.Queue + worker thread pattern from
     send_message — port into streaming.py verbatim.
     - Current color palettes from _build_native — centralize in bubble.py or
     markdown_renderer.py.

     Things we're deleting (with reason)

     ┌──────────────────────────────────────────────────────────────────────────────┬─────────────────────────────────────┐
     │                                     Item                                     │               Reason                │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ animated_text.py (314 lines)                                                 │ AnimatedText class instantiated in  │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ main.py but start_animation never called anywhere; dead code.                │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ chat_dark.css (117 lines)                                                    │ No loader; header comment of        │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ markdown_bubble.py explicitly says "avoiding HtmlFrame/tkhtml3" — CSS is not │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ rendered anywhere.                                                           │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ chat_light.css (117 lines)                                                   │ Same as above.                      │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ Pygments imports in markdown_bubble.py                                       │ PYGMENTS_AVAILABLE checked but      │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ never used to actually highlight anything.                                   │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ _DEBUG_GENERATOR_EXIT flag in main.py:983                                    │ TODO comment says "remove           │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ after testing"; testing is done.                                             │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ _bind_mousewheel, _bind_scroll_redirect_to_chat (main.py)                    │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ CTkScrollableFrame handles scroll natively.                                  │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ _init_scroll_redirect, _bind_scroll_redirect (markdown_bubble.py)            │ Same                                │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ reason — no more embedded widgets means no more redirect.                    │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ Shared velocity state for bubble scroll                                      │ Same reason.                        │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ render_user_bubble's emoji path with inner tk.Text in main.py                │ Move to                             │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ unified UserBubble class; emoji handling becomes a method on it.             │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ The 50-line container = tk.Frame(... pack_propagate(False)) wrapper in       │                                     │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ render_user_bubble                                                           │ Replaced by BubbleRow CTkFrame with │
     ├──────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────┤
     │ pack(side="right").                                                          │                                     │
     └──────────────────────────────────────────────────────────────────────────────┴─────────────────────────────────────┘

     ---
     Execution order (post-approval)

     1. Create plugins/chat/fonts.py — named tkFont.Font registry. Functions:
      get_fonts(is_dark) returns a dict of named fonts keyed by role ("body",
     "bold", "italic", "code", "h1"–"h6"), all derived from a single base size
     constant. Register fonts under stable Tk names so every tag_configure
     references them by name not object.
     2. Create plugins/chat/markdown_widgets.py — three widget classes:
       - CodeBlockWidget(CTkFrame): header row (language label + copy button),
     body tk.Text with monospace font, no scroll, state=disabled.
       - TableWidget(CTkFrame): grid of CTkLabel cells with alternating row
     backgrounds, header row bold, reflows column widths on <Configure>.
       - HorizontalRule(CTkFrame): thin colored strip via CTkFrame(height=1).
     3. Create plugins/chat/markdown_renderer.py — MarkdownRenderer class.
     Takes a parent widget and a markdown string, parses line-by-line (using the
     ported _INLINE_RE + the existing line-walk logic), and packs a mix of
     tk.Text widgets (for prose runs) and the widget classes from step 2 (for
     blocks) into the parent. Prose runs use named fonts from step 1 via
     tag_config. Start new tk.Text when switching between prose and block
     widgets.
     4. Create plugins/chat/bubble.py — BubbleRow (transparent CTkFrame,
     fill="x"), UserBubble (rounded CTkFrame with a CTkLabel or a small emoji
      tk.Text inside, packed right), AssistantBubble (rounded CTkFrame that
     hosts a MarkdownRenderer, packed left). Bubble classes expose
     set_width(max_width) for resize handling.
     AssistantBubble.set_streaming_text(text) and
     AssistantBubble.finalize_markdown(md_text) for the streaming swap.
     5. Create plugins/chat/welcome_screen.py — port the existing welcome +
     suggestion chips + API-key-missing screen into its own module. Pure UI, takes
     callbacks.
     6. Create plugins/chat/streaming.py — port the existing worker thread +
     queue.Queue + _poll_stream logic. Exposes a StreamController class with
     start(message, on_chunk, on_done, on_error) and cancel(). Runs the stream
     loop on a daemon thread, delivers chunks to the main thread via app.after(50, ...).
     7. Rewrite plugins/chat/markdown_bubble.py as a thin shim:
       - class MarkdownBubble(CTkFrame): constructor takes (master, markdown_content, **kwargs), internally constructs a MarkdownRenderer(self,
     markdown_content, ...).
       - Preserves _render_emoji, _split_emoji_chars, _emoji_cache,
     _EMOJI_RE, _EMOJI_RENDER, _is_tofu as class/static methods + module-level
     exports — the set that utils/emoji_entry.py imports.
       - Preserves _strip_inline_md and _is_box_drawing static methods —
     tests/unit/test_markdown_bubble.py depends on them.
     8. Rewrite plugins/chat/main.py:
       - Plugin class keeps its existing public API (check_status,
     reinitialize_client, send_message_to_chatgpt, create_main_screen,
     _clear_conversation) so tests/unit/test_chat_plugin.py passes unchanged.
       - create_main_screen() builds the new widget tree: CTkScrollableFrame as
     the chat area, place()-anchored input bar at the bottom (unchanged pattern).
       - send_message() creates a UserBubble + AssistantBubble row, starts a
     StreamController, streams into the assistant bubble's plain-text placeholder,
     then swaps to MarkdownRenderer on completion.
       - Auto-scroll-to-bottom check: chat_scroll._parent_canvas.yview()[1] > 0.95.
     9. Delete: animated_text.py, chat_dark.css, chat_light.css,
     tests/unit/test_animated_text.py.
     10. Run tests: ./run_tests.sh unit (must pass) and ./run_tests.sh fast
     (unit + security). Fix any regressions before proceeding.
     11. Manual smoke test on macOS (the current platform):
       - Launch: source .venv/bin/activate && python main.py -d.
       - Open chat; verify welcome screen appears.
       - Click a suggestion chip; verify request fires.
       - Send a message; verify user bubble appears right-aligned.
       - Receive response; verify streaming placeholder, then markdown render.
       - Send a message that will produce bold text in paragraphs/lists; verify
     bold is same size as body text (the primary regression check).
       - Send a message that produces a code block; verify copy button works.
       - Send a message with a table; verify it renders and reflows on window
     resize.
       - Resize the window; verify bubbles rewrap and horizontal scroll never
     appears.
       - Scroll up to history, send a new message; verify view does NOT snap to
     bottom.
       - Scroll at bottom, send a new message; verify view follows to bottom.
       - Toggle dark/light via Settings; reopen chat; verify colors match theme.
     12. Run linters from CLAUDE.md: trunk check plugins/chat/ tests/unit/test_chat_plugin.py tests/unit/test_markdown_bubble.py.
     13. Verify Help plugin still works: open Help, confirm markdown renders (it
     uses the MarkdownBubble shim now).
     14. Verify emoji input still works on Linux (if a Linux host is available):
     type a message with an emoji into the input field and verify it renders as an
     image (uses MarkdownBubble._render_emoji).

     ---
     Verification checklist

     - ./run_tests.sh unit passes (test_chat_plugin.py, test_markdown_bubble.py
      green).
     - trunk check plugins/chat/ clean.
     - Bold text in chat is visually the same size as surrounding body text (the
     reported regression).
     - No file in plugins/chat/ exceeds 300 lines.
     - markdown_bubble.py shim preserves _render_emoji, _split_emoji_chars,
      _strip_inline_md, _is_box_drawing, _EMOJI_RE, _EMOJI_RENDER exports.
     - Help plugin opens and renders markdown help pages.
     - Chat streaming: plain text during stream, markdown on completion, no
     flicker.
     - Window resize rewraps bubbles without horizontal scroll.
     - Scroll-to-bottom on new message respects user's current position.
     - Dark/light theme switch updates on plugin reload.
     - No window_create calls remain in plugins/chat/.
     - Dead files (animated_text.py, chat_*.css,
     tests/unit/test_animated_text.py) removed.

     Risks + mitigations

     ┌───────────────────────────────────────────────────────────────┬──────────────────────────────────────────┬───────────────────────────────────────┐
     │                             Risk                              │                Likelihood                │              Mitigation               │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ CTkScrollableFrame scroll feels different from current custom │                                          │                                       │
     │  inertia on                                                   │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ macOS trackpad                                                │ Medium                                   │ If users notice, add the custom       │
     │                                                               │                                          │ velocity scroll back                  │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ as a thin layer on top of CTkScrollableFrame._parent_canvas.  │                                          │                                       │
     │ The scroll                                                    │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ constants in utils/scroll.py stay available.                  │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ Help plugin breaks because MarkdownBubble shim differs subtly │                                          │                                       │
     │  from old class                                               │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ Medium                                                        │ Verify Help plugin manually after the    │                                       │
     │                                                               │ shim is written, before                  │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ deleting old code. The shim's __init__ signature is           │                                          │                                       │
     │ byte-compatible.                                              │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ emoji_entry.py breaks on Linux because static methods moved   │ Low                                      │ Keep                                  │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ static methods on MarkdownBubble shim. Linux smoke test if a  │                                          │                                       │
     │ host is                                                       │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ available.                                                    │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ Per-bubble tk.Text widgets slow down conversation rendering   │                                          │                                       │
     │ for long                                                      │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ histories                                                     │ Low                                      │ Each bubble is independent; Tk        │
     │                                                               │                                          │ handles hundreds of Text              │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ widgets fine. If we ever hit perf issues, add virtualization  │                                          │                                       │
     │ (destroy off-screen                                           │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ bubbles). Not a concern for launch.                           │                                          │                                       │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ Streaming swap (placeholder → markdown) causes visible flash  │ Low                                      │ Build the                             │
     ├───────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼───────────────────────────────────────┤
     │ MarkdownRenderer output into a hidden frame, swap in-place    │                                          │                                       │
     │ via pack_forget                                               │                                          │                                       │
     └───────────────────────────────────────────────────────────────┴──────────────────────────────────────────┴───────────────────────────────────────┘

     - pack. |
     | Breaking test_chat_plugin.py because Plugin internals changed | Medium |
     The tests only exercise the public API methods; the rewrite preserves them. Run
     tests after each major step. |