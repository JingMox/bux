# bux-unpack

Safe OCI layer extraction for the [bux](https://github.com/qntx/bux) micro-VM sandbox.

`extract_layer_files(layers, root)` applies layer tarballs (plain or gzip) to `root` in order, with OCI whiteout semantics. Every member is resolved inside `root`: symlinks are followed there and absolute targets are re-anchored at `root`, so a crafted layer cannot write or delete outside it. The Linux resolver uses `pathrs`. Device and FIFO members are skipped, and directory modes are applied after the last layer.

Part of [bux](https://github.com/qntx/bux).
