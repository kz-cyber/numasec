"""
NumaSec - PDF Exporter

Generates PDF reports using Typst.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PDFExportResult:
    """Result of PDF export."""

    success: bool
    output_path: Path | None
    error: str | None = None
    typst_output: str | None = None


class PDFExporter:
    """
    PDF exporter using Typst.

    Renders Typst templates to professional PDF reports.
    """

    def __init__(self, typst_path: str = "typst") -> None:
        """
        Initialize exporter.

        Args:
            typst_path: Path to typst binary
        """
        self.typst_path = typst_path

    def check_typst(self) -> bool:
        """Check if Typst is available."""
        try:
            result = subprocess.run(
                [self.typst_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_typst_version(self) -> str | None:
        """Get Typst version string."""
        try:
            result = subprocess.run(
                [self.typst_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    def export(
        self,
        typst_content: str,
        output_path: Path,
        *,
        font_paths: list[Path] | None = None,
        root_path: Path | None = None,
    ) -> PDFExportResult:
        """
        Export Typst content to PDF.

        Args:
            typst_content: Rendered Typst content
            output_path: Output PDF path
            font_paths: Additional font directories
            root_path: Root path for includes

        Returns:
            PDFExportResult
        """
        # Write to temp file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".typ",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(typst_content)
            temp_path = Path(f.name)

        try:
            # Build command
            cmd = [self.typst_path, "compile"]

            # Add font paths
            if font_paths:
                for fp in font_paths:
                    cmd.extend(["--font-path", str(fp)])

            # Add root path
            if root_path:
                cmd.extend(["--root", str(root_path)])

            # Add input and output
            cmd.extend([str(temp_path), str(output_path)])

            # Run Typst
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout for large reports
            )

            if result.returncode != 0:
                return PDFExportResult(
                    success=False,
                    output_path=None,
                    error=result.stderr or "Unknown Typst error",
                    typst_output=result.stdout,
                )

            return PDFExportResult(
                success=True,
                output_path=output_path,
                typst_output=result.stdout,
            )

        except subprocess.TimeoutExpired:
            return PDFExportResult(
                success=False,
                output_path=None,
                error="Typst compilation timed out (>120s)",
            )
        except FileNotFoundError:
            return PDFExportResult(
                success=False,
                output_path=None,
                error=f"Typst not found at: {self.typst_path}",
            )
        except Exception as e:
            return PDFExportResult(
                success=False,
                output_path=None,
                error=str(e),
            )
        finally:
            # Cleanup temp file
            temp_path.unlink(missing_ok=True)

    def export_file(
        self,
        typst_path: Path,
        output_path: Path,
        *,
        font_paths: list[Path] | None = None,
    ) -> PDFExportResult:
        """
        Export Typst file to PDF.

        Args:
            typst_path: Input Typst file path
            output_path: Output PDF path
            font_paths: Additional font directories

        Returns:
            PDFExportResult
        """
        if not typst_path.exists():
            return PDFExportResult(
                success=False,
                output_path=None,
                error=f"Input file not found: {typst_path}",
            )

        content = typst_path.read_text(encoding="utf-8")
        return self.export(
            content,
            output_path,
            font_paths=font_paths,
            root_path=typst_path.parent,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════


def export_to_pdf(
    typst_content: str,
    output_path: Path | str,
) -> PDFExportResult:
    """
    Quick helper to export Typst to PDF.

    Args:
        typst_content: Typst document content
        output_path: Output PDF path

    Returns:
        PDFExportResult
    """
    exporter = PDFExporter()
    return exporter.export(typst_content, Path(output_path))


def is_typst_available() -> bool:
    """Check if Typst is available on the system."""
    return PDFExporter().check_typst()
