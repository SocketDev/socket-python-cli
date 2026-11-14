"""Keeps release-specific ARGs out of the Dockerfile above its toolchain layers.

The comment above ``ARG CLI_VERSION`` in the Dockerfile explains why. A misplaced ARG fails
no build; it only turns every upgrade into a full re-pull, so it is checked here.
"""

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"
# ARGs whose values don't change between releases. Any other ARG above a
# toolchain layer fails the test.
STABLE_ARGS = {
    "GO_VERSION",
    "JAVA_VERSION",
    "DOTNET_VERSION",
    "TARGETARCH",
    "PIP_NO_CACHE_DIR",
}
TOOLCHAIN_MARKERS = ("openjdk", "dotnet", "pypy", "rustup", "pyenv")


def _instructions() -> list[str]:
    """The Dockerfile's instructions, with continuation lines joined and comments dropped."""
    instructions: list[str] = []
    current = ""
    for line in DOCKERFILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current += " " + stripped.removesuffix("\\")
        if not stripped.endswith("\\"):
            instructions.append(current.strip())
            current = ""
    return instructions


def test_only_stable_args_are_declared_above_the_toolchain_layers():
    instructions = _instructions()
    toolchain_layers = [
        i
        for i, instruction in enumerate(instructions)
        if instruction.startswith("RUN ") and any(marker in instruction for marker in TOOLCHAIN_MARKERS)
    ]
    assert len(toolchain_layers) >= len(TOOLCHAIN_MARKERS), "Dockerfile no longer installs every toolchain"
    args_above = {
        instruction.split()[1].split("=")[0]
        for instruction in instructions[: max(toolchain_layers)]
        if instruction.startswith("ARG ")
    }
    assert args_above <= STABLE_ARGS, (
        f"ARGs declared above a toolchain layer: {sorted(args_above - STABLE_ARGS)}. "
        "If their values change between releases, every release rebuilds that layer."
    )
