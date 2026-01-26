# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Constants and shared definitions for nac-validate."""


class Colors:
    """ANSI escape codes for terminal colorization."""

    # Standard colors
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"

    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Reset
    RESET = "\033[0m"

    @classmethod
    def colorize(cls, text: str, *styles: str) -> str:
        """Apply one or more styles to text.

        Args:
            text: The text to colorize
            *styles: One or more style codes (e.g., Colors.RED, Colors.BOLD)

        Returns:
            The text wrapped in ANSI codes
        """
        if not styles:
            return text
        return f"{''.join(styles)}{text}{cls.RESET}"
