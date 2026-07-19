"""
Reachability analysis package.

The main language analyzers are the public API. Selected scanners,
patterns, and dependency classifiers are also exported for testing
and advanced usage.
"""

from vulnpilot.reachability._common import (
    DependencyClassification,
    IGNORED_DIRECTORIES,
    is_ignored_file,
    is_test_file,
    line_number,
    matches_import,
)

from vulnpilot.reachability.python_dependencies import (
    classify_python_dependency,
)

from vulnpilot.reachability.python_reachability import (
    analyze_python_reachability,
    default_python_import_name,
    scan_python_imports,
)

from vulnpilot.reachability.javascript_dependencies import (
    classify_javascript_dependency,
)

from vulnpilot.reachability.javascript_reachability import (
    DYNAMIC_IMPORT_PATTERN,
    JAVASCRIPT_EXTENSIONS,
    REQUIRE_PATTERN,
    STATIC_IMPORT_PATTERN,
    analyze_javascript_reachability,
    is_probably_commented,
    matches_javascript_import,
    scan_javascript_imports,
)

from vulnpilot.reachability.java_dependencies import (
    GRADLE_DEPENDENCY_CONFIGURATIONS,
    classify_java_dependency,
    parse_java_coordinate,
)

from vulnpilot.reachability.java_reachability import (
    JAVA_EXTENSIONS,
    JAVA_IMPORT_PATTERN,
    analyze_java_reachability,
    default_java_import_names,
    detect_java_build_system,
    matches_java_import,
    scan_java_imports,
)


__all__ = [
    # Shared
    "DependencyClassification",
    "IGNORED_DIRECTORIES",
    "is_ignored_file",
    "is_test_file",
    "line_number",
    "matches_import",

    # Python
    "analyze_python_reachability",
    "classify_python_dependency",
    "default_python_import_name",
    "scan_python_imports",

    # JavaScript and TypeScript
    "DYNAMIC_IMPORT_PATTERN",
    "JAVASCRIPT_EXTENSIONS",
    "REQUIRE_PATTERN",
    "STATIC_IMPORT_PATTERN",
    "analyze_javascript_reachability",
    "classify_javascript_dependency",
    "is_probably_commented",
    "matches_javascript_import",
    "scan_javascript_imports",

    # Java, Maven and Gradle
    "GRADLE_DEPENDENCY_CONFIGURATIONS",
    "JAVA_EXTENSIONS",
    "JAVA_IMPORT_PATTERN",
    "analyze_java_reachability",
    "classify_java_dependency",
    "default_java_import_names",
    "detect_java_build_system",
    "matches_java_import",
    "parse_java_coordinate",
    "scan_java_imports",
]
