package(default_visibility = ["//visibility:public"])

exports_files([
    "conf.py",
    "index.rst",
])

sh_binary(
    name = "docs",
    srcs = ["docs_runner.sh"],
    data = [
        "conf.py",
        "index.rst",
        "//:rust_srcs",
    ],
)
