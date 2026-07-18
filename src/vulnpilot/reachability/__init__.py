"""
Reachability analysis package.

Re-exports all public symbols from the language-specific modules so
that existing ``from vulnpilot.reachability import …`` statements
continue to work without modification.
"""

from vulnpilot.reachability._common import (
    IGNORED_DIRECTORIES,
    is_ignored_file,
    is_test_file,
    matches_import,
    line_number,
)

from vulnpilot.reachability.python_reachability import (
    default_python_import_name,
    scan_python_imports,
    analyze_python_reachability,
)

from vulnpilot.reachability.javascript_reachability import (
    JAVASCRIPT_EXTENSIONS,
    STATIC_IMPORT_PATTERN,
    REQUIRE_PATTERN,
    DYNAMIC_IMPORT_PATTERN,
    matches_javascript_import,
    is_probably_commented,
    scan_javascript_imports,
    analyze_javascript_reachability,
)

from vulnpilot.reachability.java_reachability import (
    JAVA_EXTENSIONS,
    JAVA_IMPORT_PATTERN,
    GRADLE_DEPENDENCY_CONFIGURATIONS,
    matches_java_import,
    default_java_import_names,
    scan_java_imports,
    xml_local_name,
    xml_child_text,
    is_maven_dependency_direct,
    has_direct_maven_dependency,
    gradle_dependency_pattern,
    has_direct_gradle_dependency,
    detect_java_build_system,
    analyze_java_reachability,
)

__all__ = [
    # _common
    "IGNORED_DIRECTORIES",
    "is_ignored_file",
    "is_test_file",
    "matches_import",
    "line_number",
    # python
    "default_python_import_name",
    "scan_python_imports",
    "analyze_python_reachability",
    # javascript
    "JAVASCRIPT_EXTENSIONS",
    "STATIC_IMPORT_PATTERN",
    "REQUIRE_PATTERN",
    "DYNAMIC_IMPORT_PATTERN",
    "matches_javascript_import",
    "is_probably_commented",
    "scan_javascript_imports",
    "analyze_javascript_reachability",
    # java
    "JAVA_EXTENSIONS",
    "JAVA_IMPORT_PATTERN",
    "GRADLE_DEPENDENCY_CONFIGURATIONS",
    "matches_java_import",
    "default_java_import_names",
    "scan_java_imports",
    "xml_local_name",
    "xml_child_text",
    "is_maven_dependency_direct",
    "has_direct_maven_dependency",
    "gradle_dependency_pattern",
    "has_direct_gradle_dependency",
    "detect_java_build_system",
    "analyze_java_reachability",
]
