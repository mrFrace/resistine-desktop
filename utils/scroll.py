"""
Per-platform scroll speed constants.

Centralises every tuneable so that adjusting scroll feel is a single-file change.
"""

import sys

_IS_MAC = sys.platform == "darwin"
_IS_LINUX = sys.platform.startswith("linux")

# -- Chat / bubble text-widget scrolling (yview_scroll in pixels) -----------

# Velocity added per discrete scroll notch (Button-4 / Button-5 on Linux).
CHAT_SCROLL_DELTA = 16.0 if _IS_LINUX else 0.5

# Multiplier applied to MouseWheel event.delta.
# Linux/Windows: deltas come in ±120 per notch (Win32 / X11). The handler
# normalizes by /120 then multiplies by 16, so each notch contributes ±16
# of velocity to the smooth-scroll integrator — same target on either OS.
# macOS: deltas are raw (trackpad ~1-10 per event, mouse wheel typically 1
# per notch), multiplied directly. 2.0 is the compromise — gives a Mac mouse
# wheel ~2 velocity per notch (still slower than Win/Linux's 16, but visibly
# more responsive than the previous 0.4 which made wheel scrolling feel
# stuck) without sending the trackpad past CHAT_VEL_CLAMP on every flick.
CHAT_WHEEL_SCALE = 2.0 if _IS_MAC else 16.0

# Velocity is clamped to ±CHAT_VEL_CLAMP after every input event.
CHAT_VEL_CLAMP = 20.0

# Velocity below this threshold stops the animation.
CHAT_VEL_THRESHOLD = 0.5

# Multiply velocity by this each 8 ms step (lower = faster deceleration).
CHAT_VEL_DECAY = 0.88

# -- Dashboard / CTkScrollableFrame scrolling (pixel-based, mirrors chat) ------
# Uses canvas.yview_scroll in pixels (via yscrollincrement=1) so scroll speed
# is consistent regardless of page length — same constants as chat.

# Velocity added per discrete scroll notch (Button-4 / Button-5 on Linux).
FRAME_SCROLL_DELTA = CHAT_SCROLL_DELTA

# Multiplier applied to MouseWheel event.delta (same as chat).
FRAME_WHEEL_SCALE = CHAT_WHEEL_SCALE

# Velocity is clamped to ±FRAME_VEL_CLAMP.
FRAME_VEL_CLAMP = CHAT_VEL_CLAMP

# Velocity below this threshold stops the animation.
FRAME_VEL_THRESHOLD = CHAT_VEL_THRESHOLD

# Decay factor applied each 8 ms step.
FRAME_VEL_DECAY = CHAT_VEL_DECAY
