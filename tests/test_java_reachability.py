from vulnpilot.reachability import (
    analyze_java_reachability,
)


def test_detects_maven_dependency_and_import(
    tmp_path,
):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    source_directory = (
        tmp_path / "src" / "main" / "java"
    )
    source_directory.mkdir(parents=True)

    source_file = source_directory / "App.java"
    source_file.write_text(
        """
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "org.apache.logging.log4j:log4j-core"
        ),
    )

    assert result.build_system == "maven"
    assert result.dependency_type == "direct"
    assert result.usage_found is True
    assert result.production_usage_found is True
    assert result.test_only is False
    assert result.reachability == "likely"
    assert len(result.used_in) == 2


def test_detects_gradle_dependency(
    tmp_path,
):
    build_file = tmp_path / "build.gradle.kts"
    build_file.write_text(
        """
dependencies {
    implementation(
        "org.apache.logging.log4j:log4j-core:2.14.1"
    )
}
""".strip(),
        encoding="utf-8",
    )

    source_directory = (
        tmp_path / "src" / "main" / "java"
    )
    source_directory.mkdir(parents=True)

    source_file = source_directory / "App.java"
    source_file.write_text(
        """
import org.apache.logging.log4j.LogManager;

public class App {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "org.apache.logging.log4j:log4j-core"
        ),
    )

    assert result.build_system == "gradle"
    assert result.dependency_type == "direct"
    assert result.usage_found is True
    assert result.reachability == "likely"


def test_detects_static_java_import(
    tmp_path,
):
    source_file = tmp_path / "App.java"
    source_file.write_text(
        """
import static org.apache.logging.log4j.Level.ERROR;

public class App {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "org.apache.logging.log4j:log4j-core"
        ),
    )

    assert result.usage_found is True
    assert (
        result.used_in[0].imported_name
        == "org.apache.logging.log4j.Level.ERROR"
    )


def test_marks_java_test_only_usage(
    tmp_path,
):
    test_directory = (
        tmp_path / "src" / "test" / "java"
    )
    test_directory.mkdir(parents=True)

    test_file = test_directory / "ExampleTest.java"
    test_file.write_text(
        """
import org.junit.jupiter.api.Test;

public class ExampleTest {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name="org.junit.jupiter:junit-jupiter",
    )

    assert result.usage_found is True
    assert result.production_usage_found is False
    assert result.test_only is True
    assert result.reachability == "unlikely"


def test_supports_custom_java_import_prefix(
    tmp_path,
):
    source_file = tmp_path / "ObjectMapperExample.java"
    source_file.write_text(
        """
import com.fasterxml.jackson.databind.ObjectMapper;

public class ObjectMapperExample {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "com.fasterxml.jackson.core:jackson-databind"
        ),
        import_names=[
            "com.fasterxml.jackson.databind",
        ],
    )

    assert result.usage_found is True
    assert result.reachability == "likely"


def test_does_not_match_similar_java_package(
    tmp_path,
):
    source_file = tmp_path / "App.java"
    source_file.write_text(
        """
import org.apache.logging.other.Logger;

public class App {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "org.apache.logging.log4j:log4j-core"
        ),
    )

    assert result.usage_found is False


def test_dependency_management_is_not_direct(
    tmp_path,
):
    pom = tmp_path / "pom.xml"
    pom.write_text(
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

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name="org.example:example-library",
    )

    assert result.build_system == "maven"
    assert result.dependency_type == "unknown"

def test_java_reachability_includes_dependency_type(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    source_directory = (
        tmp_path / "src" / "main" / "java"
    )
    source_directory.mkdir(parents=True)

    (
        source_directory / "Application.java"
    ).write_text(
        """
import org.apache.logging.log4j.LogManager;

public class Application {
}
""".strip(),
        encoding="utf-8",
    )

    result = analyze_java_reachability(
        project_path=str(tmp_path),
        package_name=(
            "org.apache.logging.log4j:log4j-core"
        ),
    )

    assert result.dependency_type == "direct"
    assert "pom.xml" in (
        result.dependency_evidence[0]
    )
    assert result.usage_found is True
    assert result.reachability == "likely"
