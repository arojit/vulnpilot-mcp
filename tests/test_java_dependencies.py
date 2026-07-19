from vulnpilot.reachability.java_dependencies import (
    classify_java_dependency,
)


def test_maven_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.example</groupId>
            <artifactId>example-library</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "direct"
    assert "pom.xml" in result.evidence[0]


def test_dependency_management_is_not_direct(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        """
<project>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.example</groupId>
                <artifactId>example-library</artifactId>
                <version>1.0.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "unknown"


def test_maven_tree_dependency_is_transitive(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>6.0.0</version>
        </dependency>
    </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    report_directory = (
        tmp_path / ".vulnpilot"
    )
    report_directory.mkdir()

    (
        report_directory
        / "maven-dependency-tree.txt"
    ).write_text(
        """
[INFO] com.example:app:jar:1.0
[INFO] +- org.springframework:spring-web:jar:6.0.0:compile
[INFO] |  \\- org.springframework:spring-core:jar:6.0.0:compile
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.springframework:spring-core"
        ),
    )

    assert result.dependency_type == "transitive"
    assert (
        "maven-dependency-tree.txt"
        in result.evidence[0]
    )


def test_gradle_string_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "build.gradle.kts").write_text(
        """
dependencies {
    implementation(
        "org.example:example-library:1.0.0"
    )
}
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "direct"
    assert "build.gradle.kts" in (
        result.evidence[0]
    )


def test_gradle_map_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "build.gradle").write_text(
        """
dependencies {
    implementation group: "org.example",
                   name: "example-library",
                   version: "1.0.0"
}
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "direct"


def test_gradle_report_dependency_is_transitive(
    tmp_path,
):
    (tmp_path / "build.gradle").write_text(
        """
dependencies {
    implementation "org.springframework:spring-web:6.0.0"
}
""".strip(),
        encoding="utf-8",
    )

    report_directory = (
        tmp_path / ".vulnpilot"
    )
    report_directory.mkdir()

    (
        report_directory
        / "gradle-dependencies.txt"
    ).write_text(
        """
+--- org.springframework:spring-web:6.0.0
|    \\--- org.springframework:spring-core:6.0.0
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.springframework:spring-core"
        ),
    )

    assert result.dependency_type == "transitive"


def test_gradle_lock_dependency_is_transitive(
    tmp_path,
):
    (tmp_path / "build.gradle.kts").write_text(
        """
dependencies {
    implementation(
        "org.springframework:spring-web:6.0.0"
    )
}
""".strip(),
        encoding="utf-8",
    )

    (tmp_path / "gradle.lockfile").write_text(
        """
org.springframework:spring-core:6.0.0=runtimeClasspath
org.springframework:spring-web:6.0.0=runtimeClasspath
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.springframework:spring-core"
        ),
    )

    assert result.dependency_type == "transitive"
    assert "gradle.lockfile" in (
        result.evidence[0]
    )


def test_direct_declaration_beats_report(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.example</groupId>
            <artifactId>example-library</artifactId>
        </dependency>
    </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    (
        tmp_path / "dependency-tree.txt"
    ).write_text(
        """
[INFO] +- org.example:example-library:jar:1.0:compile
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "direct"


def test_report_without_manifest_is_unknown(
    tmp_path,
):
    (
        tmp_path / "dependency-tree.txt"
    ).write_text(
        """
[INFO] +- org.example:example-library:jar:1.0:compile
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "unknown"


def test_similar_artifact_is_not_matched(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        "<project></project>",
        encoding="utf-8",
    )

    (
        tmp_path / "dependency-tree.txt"
    ).write_text(
        """
[INFO] +- org.example:example-library-extra:jar:1.0:compile
""".strip(),
        encoding="utf-8",
    )

    result = classify_java_dependency(
        project_path=tmp_path,
        package_name=(
            "org.example:example-library"
        ),
    )

    assert result.dependency_type == "unknown"


def test_invalid_coordinate_is_unknown(
    tmp_path,
):
    result = classify_java_dependency(
        project_path=tmp_path,
        package_name="example-library",
    )

    assert result.dependency_type == "unknown"
    assert "groupId:artifactId" in (
        result.evidence[0]
    )
