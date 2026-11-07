"""Release-lab controller package.

The controller deliberately keeps its state outside the checkout.  The
checkout contains profiles and code; the WSL lab owns images, overlays, QEMU
state and evidence.
"""

__all__ = ["__version__"]
__version__ = "0.1"
