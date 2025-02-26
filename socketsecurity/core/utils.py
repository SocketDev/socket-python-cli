
# File pattern definitions
socket_globs = {
    "spdx": {
        "spdx.json": {
            "pattern": "*[-.]spdx.json"
        }
    },
    "cdx": {
        "cyclonedx.json": {
            "pattern": "{bom,*[-.]c{yclone,}dx}.json"
        },
        "xml": {
            "pattern": "{bom,*[-.]c{yclone,}dx}.xml"
        }
    },
    "npm": {
        "package.json": {
            "pattern": "package.json"
        },
        "package-lock.json": {
            "pattern": "package-lock.json"
        },
        "npm-shrinkwrap.json": {
            "pattern": "npm-shrinkwrap.json"
        },
        "yarn.lock": {
            "pattern": "yarn.lock"
        },
        "pnpm-lock.yaml": {
            "pattern": "pnpm-lock.yaml"
        },
        "pnpm-lock.yml": {
            "pattern": "pnpm-lock.yml"
        },
        "pnpm-workspace.yaml": {
            "pattern": "pnpm-workspace.yaml"
        },
        "pnpm-workspace.yml": {
            "pattern": "pnpm-workspace.yml"
        }
    },
    "pypi": {
        "pipfile": {
            "pattern": "pipfile"
        },
        "pyproject.toml": {
            "pattern": "pyproject.toml"
        },
        "poetry.lock": {
            "pattern": "poetry.lock"
        },
        "requirements.txt": {
            "pattern": "*requirements.txt"
        },
        "requirements": {
            "pattern": "requirements/*.txt"
        },
        "requirements-*.txt": {
            "pattern": "requirements-*.txt"
        },
        "requirements_*.txt": {
            "pattern": "requirements_*.txt"
        },
        "requirements.frozen": {
            "pattern": "requirements.frozen"
        },
        "setup.py": {
            "pattern": "setup.py"
        }
    },
    "golang": {
        "go.mod": {
            "pattern": "go.mod"
        },
        "go.sum": {
            "pattern": "go.sum"
        }
    },
    "java": {
        "pom.xml": {
            "pattern": "pom.xml"
        }
    },
    ".net": {
        "proj": {
            "pattern": "*.*proj"
        },
        "props": {
            "pattern": "*.props"
        },
        "targets": {
            "pattern": "*.targets"
        },
        "nuspec": {
            "pattern": "*.nuspec"
        },
        "nugetConfig": {
            "pattern": "nuget.config"
        },
        "packagesConfig": {
            "pattern": "packages.config"
        },
        "packagesLock": {
            "pattern": "packages.lock.json"
        }
    }
}