package(default_visibility = ["//visibility:public"])

exports_files([
    "conf.py",
    "index.rst",
])

genrule(
    name = "docs",
    outs = ["docs_runner.sh"],
    cmd = "echo '#!/bin/bash\necho \"Docs tool initialized. Arguments received: $$@\"' > $@",
    executable = True,
)
