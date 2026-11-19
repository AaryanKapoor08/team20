"""The shared look for every experiment chart.

All charts are black, white and grey, so they print and copy into the report
cleanly and nothing depends on telling red from green. Results are told apart
by how dark a box is: a dark box means the attacker won, a white box means a
defence held, and a pale box means that part was never checked.
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

INK = "#09090b"
MID = "#a1a1aa"
PALE = "#d4d4d8"
PAPER = "#ffffff"

# the fill for each kind of result, and the text colour on it
FILLS = {
    "dark": (INK, PAPER),
    "light": (PAPER, INK),
    "pale": (PALE, INK),
}


def use_plain_style() -> None:
    """Set the fonts, colours and spacing used by all the charts."""
    plt.rcParams.update({
        "figure.facecolor": PAPER,
        "axes.facecolor": PAPER,
        "axes.edgecolor": PALE,
        "axes.labelcolor": INK,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.titlecolor": INK,
        "axes.labelsize": 9,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "text.color": INK,
        "xtick.color": "#71717a",
        "ytick.color": "#71717a",
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "grid.color": "#e4e4e7",
        "font.size": 9,
    })


def draw_cell(axes, column: int, row: int, label: str, fill: str) -> None:
    """Draw one result box with its label inside it."""
    face, text_colour = FILLS[fill]
    box = plt.Rectangle(
        (column + 0.04, row + 0.06), 0.92, 0.88,
        facecolor=face, edgecolor=INK, linewidth=1,
    )
    axes.add_patch(box)
    axes.text(
        column + 0.5, row + 0.5, label,
        ha="center", va="center", color=text_colour, fontsize=9, wrap=True,
    )


def hide_axis_lines(axes) -> None:
    """Take the box off a chart that is only made of result cells."""
    for side in ["top", "right", "bottom", "left"]:
        axes.spines[side].set_visible(False)
