"""Command-line entrypoint for provenance graph conversion."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from provenance_graph.converter import ProvenanceConversionError, convert_catalog, convert_dataset

APP = typer.Typer(no_args_is_help=True, help="Convert EvidenceForge data to provenance graphs.")
CONSOLE = Console()
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@APP.command("convert-all")
def convert_all(
    catalog: Path = typer.Option(
        REPOSITORY_ROOT / "provenance_graph" / "datasets.json",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Portable seven-dataset catalog.",
    ),
    output: Path = typer.Option(
        REPOSITORY_ROOT / "provenance_graph" / "graphs",
        file_okay=False,
        resolve_path=True,
        help="Generated graph artifact directory.",
    ),
    include_offline_labels: bool = typer.Option(
        True,
        "--include-offline-labels/--no-offline-labels",
        help="Write physically separate offline evaluation labels.",
    ),
) -> None:
    """Convert all seven configured datasets."""
    try:
        results = convert_catalog(
            repository_root=REPOSITORY_ROOT,
            catalog_path=catalog,
            output_root=output,
            include_offline_labels=include_offline_labels,
        )
    except ProvenanceConversionError as exc:
        CONSOLE.print(f"[red]Conversion failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Provenance graph conversion")
    table.add_column("Dataset")
    table.add_column("Nodes", justify="right")
    table.add_column("Edges", justify="right")
    table.add_column("Malicious edges", justify="right")
    table.add_column("Readiness", justify="right")
    for result in results:
        score = f"{result.readiness_score:.2f}" if result.readiness_score is not None else "n/a"
        table.add_row(
            result.dataset,
            str(result.node_count),
            str(result.edge_count),
            str(result.malicious_edge_count),
            score,
        )
    CONSOLE.print(table)
    CONSOLE.print(f"Artifacts: {output}")


@APP.command("convert-one")
def convert_one(
    dataset_root: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        readable=True,
        resolve_path=True,
        help="EvidenceForge output root containing data/.",
    ),
    output: Path = typer.Option(
        REPOSITORY_ROOT / "provenance_graph" / "graphs",
        file_okay=False,
        resolve_path=True,
    ),
    name: str | None = typer.Option(None, help="Output dataset name; defaults to directory name."),
) -> None:
    """Convert one EvidenceForge dataset."""
    try:
        result = convert_dataset(
            dataset_name=name or dataset_root.name,
            dataset_root=dataset_root,
            output_root=output,
        )
    except ProvenanceConversionError as exc:
        CONSOLE.print(f"[red]Conversion failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    CONSOLE.print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    APP()
