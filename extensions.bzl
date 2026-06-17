load("//toolchains:rules.bzl", "qcc_toolchain")

def _local_sdp_impl(rctx):
    rctx.file("WORKSPACE.bazel", "")

    rctx.template("BUILD.bazel", rctx.attr.build_file, {})

    qnx_path = rctx.path(rctx.attr.path)
    for item in qnx_path.readdir():
        if item.basename not in ["BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "REPO.bazel"]:
            rctx.symlink(item, item.basename)

local_sdp = repository_rule(
    implementation = _local_sdp_impl,
    attrs = {
        "path": attr.string(mandatory = True),
        "build_file": attr.label(mandatory = True),
    },
)

def _toolchains_qnx_impl(mctx):
    local_sdp(
        name = "toolchains_qnx_sdp",
        path = "/home/oeweda/qnx800",
        build_file = "//toolchains:sdp.BUILD",
    )

    qcc_toolchain(
        name = "toolchains_qnx_qcc",
        sdp_repo = "toolchains_qnx_sdp",
        sdp_version = "8.0.0",
        qcc_version = "12.2.0",
    )

toolchains_qnx = module_extension(implementation = _toolchains_qnx_impl)
