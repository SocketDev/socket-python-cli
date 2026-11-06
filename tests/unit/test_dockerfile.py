"""Keeps the Dockerfile's release ARGs below its toolchain layers.

The comment above ``ARG CLI_VERSION`` in the Dockerfile explains why. A misplaced ARG fails
no build; it only turns every upgrade into a full re-pull, so it is checked here.
"""

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"
RELEASE_ARGS = {
    "CLI_VERSION",
    "SDK_VERSION",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "USE_LOCAL_INSTALL",
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


def test_release_args_are_declared_after_the_toolchain_layers():
    instructions = _instructions()
    release_args = [
        i
        for i, instruction in enumerate(instructions)
        if instruction.startswith("ARG ")
        and instruction.split()[1].split("=")[0] in RELEASE_ARGS
    ]
    toolchain_layers = [
        i
        for i, instruction in enumerate(instructions)
        if instruction.startswith("RUN ")
        and any(marker in instruction for marker in TOOLCHAIN_MARKERS)
    ]
    assert len(release_args) == len(RELEASE_ARGS), (
        "Dockerfile no longer declares every release ARG"
    )
    assert len(toolchain_layers) >= len(TOOLCHAIN_MARKERS), (
        "Dockerfile no longer installs every toolchain"
    )
    assert min(release_args) > max(toolchain_layers), (
        "A release ARG is declared above a toolchain layer, so every release would rebuild it"
    )
