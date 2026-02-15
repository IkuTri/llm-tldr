"""UE5-specific dead code filter.

Unreal Engine 5 uses a reflection system (UHT) that calls functions at runtime
via mechanisms invisible to static C++ analysis:
- UFUNCTION() annotated functions are callable from Blueprints, delegates, RPCs, timers
- Engine lifecycle overrides (BeginPlay, Tick, etc.) are called by the engine automatically
- Constructors/destructors are called implicitly
- GENERATED_BODY() produces functions tree-sitter might pick up

This module scans header files for these patterns and provides a filter
that dead code analysis can use to suppress false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# Engine lifecycle overrides that are called automatically by UE5.
# These are virtual functions inherited from UE base classes.
UE5_LIFECYCLE_OVERRIDES: set[str] = {
    # AActor / UActorComponent lifecycle
    "BeginPlay",
    "EndPlay",
    "Tick",
    "TickComponent",
    "BeginDestroy",
    "FinishDestroy",
    "PostInitializeComponents",
    "PreInitializeComponents",

    # UObject lifecycle
    "PostInitProperties",
    "PostLoad",
    "PreSave",
    "Serialize",
    "PostEditChangeProperty",
    "PostEditChangeChainProperty",

    # Replication
    "GetLifetimeReplicatedProps",
    "PreReplication",
    "OnRep_Owner",

    # Pawn / Character
    "SetupPlayerInputComponent",
    "PossessedBy",
    "UnPossessed",
    "OnRep_PlayerState",
    "OnRep_Controller",
    "Restart",

    # Controller
    "InitPlayerState",
    "OnPossess",
    "OnUnPossess",
    "SetupInputComponent",

    # Animation
    "NativeInitializeAnimation",
    "NativeUpdateAnimation",
    "NativeBeginPlay",

    # GameplayAbility (GAS)
    "ActivateAbility",
    "EndAbility",
    "CanActivateAbility",
    "InputPressed",
    "InputReleased",
    "CancelAbility",
    "CommitAbility",
    "CommitCheck",
    "ApplyGameplayEffectToOwner",

    # GameplayEffect (GAS execution calcs)
    "Execute_Implementation",

    # UGameInstanceSubsystem / UWorldSubsystem / ULocalPlayerSubsystem
    "Initialize",
    "Deinitialize",
    "Shutdown",
    "ShouldCreateSubsystem",

    # USubsystem
    "PostInitialize",

    # GameMode / GameState
    "InitGame",
    "InitGameState",
    "StartPlay",
    "HandleMatchIsWaitingToStart",
    "HandleMatchHasStarted",
    "HandleMatchHasEnded",

    # PlayerController
    "BeginPlayingState",
    "SetPlayer",
    "ReceivedPlayer",

    # HUD
    "DrawHUD",

    # Widget (UMG / Slate)
    "NativeConstruct",
    "NativeDestruct",
    "NativeTick",
    "NativeOnInitialized",

    # Movement component
    "TickComponent",
    "PhysicsVolumeChanged",

    # GMC-specific (General Movement Component)
    "BindReplicationData",
    "MovementUpdate",
    "GenPredictionTick",
    "GenSimulationTick",
    "GenAncillaryTick",
    "OnSyncDataApplied",
    "PreMovementUpdate",
    "PostMovementUpdate",
    "PreSimulatedMoveExecution",

    # GMAS (GMC Ability System)
    "CheckPreconditions",
    "OnAbilityGranted",
    "OnAbilityActivated",
    "OnAbilityEnded",
    "GetActiveEffectContainers",
}

# UPROPERTY meta functions often generated or called via reflection
UE5_PROPERTY_CALLBACKS: set[str] = {
    # OnRep_ callbacks are called by the replication system
    # We match these by prefix below, not by exact name
}

# Regex to detect UFUNCTION() macro (possibly multiline)
_UFUNCTION_RE = re.compile(
    r"^\s*UFUNCTION\s*\(",
    re.MULTILINE,
)

# Regex to extract function name from a C++ declaration line
# Matches: ReturnType FuncName(  or  ReturnType ClassName::FuncName(
# Also handles: virtual, static, FORCEINLINE, const, IKUSOFT_API, etc.
_FUNC_DECL_RE = re.compile(
    r"""
    (?:virtual\s+)?          # optional virtual
    (?:static\s+)?           # optional static
    (?:FORCEINLINE\s+)?      # optional FORCEINLINE
    (?:inline\s+)?           # optional inline
    (?:\w+_API\s+)?          # optional MODULE_API export macro
    [\w\*&:<>,\s]+?          # return type (greedy but lazy enough)
    \b([\w~]+)               # function name (captured)
    \s*\(                    # opening paren
    """,
    re.VERBOSE,
)

# Regex for constructor/destructor patterns
# ClassName::ClassName or ClassName::~ClassName
_CTOR_DTOR_RE = re.compile(r"^(\w+)::~?\1$")


@dataclass
class UE5FilterResult:
    """Results from UE5 dead code filtering."""

    ufunction_names: set[str] = field(default_factory=set)
    lifecycle_filtered: list[str] = field(default_factory=list)
    ufunction_filtered: list[str] = field(default_factory=list)
    constructor_filtered: list[str] = field(default_factory=list)
    onrep_filtered: list[str] = field(default_factory=list)

    @property
    def all_filtered(self) -> set[str]:
        """All function names that were filtered out."""
        return set(
            self.lifecycle_filtered
            + self.ufunction_filtered
            + self.constructor_filtered
            + self.onrep_filtered
        )

    def summary(self) -> str:
        """Human-readable summary of what was filtered."""
        parts = []
        if self.ufunction_filtered:
            parts.append(f"{len(self.ufunction_filtered)} UFUNCTION")
        if self.lifecycle_filtered:
            parts.append(f"{len(self.lifecycle_filtered)} lifecycle")
        if self.constructor_filtered:
            parts.append(f"{len(self.constructor_filtered)} constructor/destructor")
        if self.onrep_filtered:
            parts.append(f"{len(self.onrep_filtered)} OnRep callback")
        if not parts:
            return "No UE5 functions filtered"
        return f"Filtered {', '.join(parts)}"


def scan_ufunction_names(project_path: str | Path) -> set[str]:
    """Scan all .h files in a project for UFUNCTION()-annotated function names.

    The UFUNCTION() macro appears on the line(s) before the function declaration.
    We find each UFUNCTION( block, skip past its closing ), then parse the
    next non-empty line for the function name.

    Args:
        project_path: Root directory to scan

    Returns:
        Set of function names that have UFUNCTION() annotation
    """
    project_path = Path(project_path)
    ufunction_names: set[str] = set()

    for header_file in _iter_headers(project_path):
        try:
            content = header_file.read_text(encoding="utf-8", errors="replace")
            names = _extract_ufunction_names(content)
            ufunction_names.update(names)
        except (OSError, UnicodeDecodeError):
            continue

    return ufunction_names


def _iter_headers(project_path: Path) -> Iterator[Path]:
    """Iterate over all C++ header files in a project."""
    for ext in ("*.h", "*.hpp"):
        yield from project_path.rglob(ext)


def _extract_ufunction_names(content: str) -> set[str]:
    """Extract function names annotated with UFUNCTION() from file content.

    Strategy:
    1. Find each UFUNCTION( occurrence
    2. Track parenthesis nesting to find the closing )
    3. The function declaration follows on subsequent lines
    4. Extract the function name from the declaration
    """
    names: set[str] = set()
    lines = content.split("\n")

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for UFUNCTION( on this line
        if re.match(r"\s*UFUNCTION\s*\(", line):
            # Find the end of the UFUNCTION() macro (handle multiline)
            paren_depth = 0
            j = i
            found_end = False

            while j < len(lines):
                for ch in lines[j]:
                    if ch == "(":
                        paren_depth += 1
                    elif ch == ")":
                        paren_depth -= 1
                        if paren_depth == 0:
                            found_end = True
                            break
                if found_end:
                    break
                j += 1

            if not found_end:
                i += 1
                continue

            # Now look at lines after the UFUNCTION() macro for the function declaration
            # It's typically on the next line or a few lines down (past comments/whitespace)
            for k in range(j + 1, min(j + 5, len(lines))):
                decl_line = lines[k].strip()

                # Skip empty lines and comments
                if not decl_line or decl_line.startswith("//") or decl_line.startswith("/*"):
                    continue

                # Skip additional macros that might appear between UFUNCTION and declaration
                if decl_line.startswith("UPROPERTY") or decl_line.startswith("UFUNCTION"):
                    break  # Hit another macro, stop looking

                # Try to extract function name
                name = _extract_func_name_from_decl(decl_line)
                if name:
                    names.add(name)
                break

            i = j + 1
        else:
            i += 1

    return names


def _extract_func_name_from_decl(line: str) -> str | None:
    """Extract function name from a C++ declaration line.

    Examples:
        'void MyFunction();'                    -> 'MyFunction'
        'UCapsuleComponent* GetCapsule() const' -> 'GetCapsule'
        'virtual void BeginPlay() override;'    -> 'BeginPlay'
        'UCLASS_API int32 GetTeamID() const;'   -> 'GetTeamID'
        'void Server_Respawn();'                -> 'Server_Respawn'
        'TArray<FName> GetNames() const;'       -> 'GetNames'
    """
    # Strip trailing qualifiers for cleaner matching
    clean = line.rstrip(";").strip()

    # Remove trailing const, override, final, = 0, etc.
    clean = re.sub(r"\)\s*(const)?\s*(override)?\s*(final)?\s*(=\s*0)?\s*$", ")", clean)

    # Find the function name: the identifier immediately before (
    # Walk backward from the first ( to find the name
    paren_pos = clean.find("(")
    if paren_pos < 0:
        return None

    # Get everything before the (
    before_paren = clean[:paren_pos].rstrip()

    # The function name is the last word/identifier
    # Handle templates: if there's a >, skip back past the template
    if before_paren.endswith(">"):
        # Find matching <
        depth = 0
        for idx in range(len(before_paren) - 1, -1, -1):
            if before_paren[idx] == ">":
                depth += 1
            elif before_paren[idx] == "<":
                depth -= 1
                if depth == 0:
                    before_paren = before_paren[:idx].rstrip()
                    break

    # Split on whitespace and non-identifier chars, take last word
    parts = re.split(r"[\s*&]+", before_paren)
    # Filter out empty strings and type qualifiers
    parts = [p for p in parts if p and not p.startswith("(")]

    if not parts:
        return None

    name = parts[-1]

    # Clean up any remaining non-identifier chars
    name = re.sub(r"[^a-zA-Z0-9_~]", "", name)

    if not name or name in ("virtual", "static", "inline", "FORCEINLINE",
                            "void", "int", "float", "bool", "class", "struct",
                            "const", "unsigned", "signed"):
        return None

    return name


def is_constructor_or_destructor(func_name: str) -> bool:
    """Check if a function name looks like a constructor or destructor.

    Handles:
    - ClassName::ClassName (qualified constructor)
    - ClassName::~ClassName (qualified destructor)
    - Simple names that match class naming (less reliable, but catches
      functions like 'AIKU_Character' extracted without qualification)
    """
    # Qualified form: X::X or X::~X
    if "::" in func_name:
        return bool(_CTOR_DTOR_RE.match(func_name))

    # Destructor prefix
    if func_name.startswith("~"):
        return True

    return False


def is_lifecycle_override(func_name: str) -> bool:
    """Check if a function name is a known UE5 engine lifecycle override."""
    # Strip class qualification if present
    bare_name = func_name.split("::")[-1] if "::" in func_name else func_name
    return bare_name in UE5_LIFECYCLE_OVERRIDES


def is_onrep_callback(func_name: str) -> bool:
    """Check if a function name is an OnRep_ replication callback."""
    bare_name = func_name.split("::")[-1] if "::" in func_name else func_name
    return bare_name.startswith("OnRep_")


def filter_dead_functions(
    dead_functions: list[dict],
    project_path: str | Path,
    show_filtered: bool = False,
) -> tuple[list[dict], UE5FilterResult]:
    """Filter UE5 false positives from dead code results.

    Args:
        dead_functions: List of {file, function} dicts from dead_code_analysis
        project_path: Project root (for scanning headers)
        show_filtered: If True, populate detailed filter result lists

    Returns:
        Tuple of (filtered_dead_functions, filter_result)
    """
    result = UE5FilterResult()

    # Scan for UFUNCTION-annotated names
    result.ufunction_names = scan_ufunction_names(project_path)

    surviving = []

    for func_info in dead_functions:
        func_name = func_info["function"]
        bare_name = func_name.split("::")[-1] if "::" in func_name else func_name

        # Check UFUNCTION annotation
        if bare_name in result.ufunction_names:
            if show_filtered:
                result.ufunction_filtered.append(func_name)
            continue

        # Check lifecycle overrides
        if is_lifecycle_override(func_name):
            if show_filtered:
                result.lifecycle_filtered.append(func_name)
            continue

        # Check constructor/destructor
        if is_constructor_or_destructor(func_name):
            if show_filtered:
                result.constructor_filtered.append(func_name)
            continue

        # Check OnRep_ callbacks
        if is_onrep_callback(func_name):
            if show_filtered:
                result.onrep_filtered.append(func_name)
            continue

        surviving.append(func_info)

    # If not show_filtered, still count what we filtered for the summary
    if not show_filtered:
        total_filtered = len(dead_functions) - len(surviving)
        if total_filtered > 0:
            # Do a second pass just for counts
            for func_info in dead_functions:
                if func_info in surviving:
                    continue
                func_name = func_info["function"]
                bare_name = func_name.split("::")[-1] if "::" in func_name else func_name

                if bare_name in result.ufunction_names:
                    result.ufunction_filtered.append(func_name)
                elif is_lifecycle_override(func_name):
                    result.lifecycle_filtered.append(func_name)
                elif is_constructor_or_destructor(func_name):
                    result.constructor_filtered.append(func_name)
                elif is_onrep_callback(func_name):
                    result.onrep_filtered.append(func_name)

    return surviving, result
