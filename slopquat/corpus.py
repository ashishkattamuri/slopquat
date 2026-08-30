"""Bundled reference data for slopquat.

Everything in this module is common-knowledge, registry-checkable, or trivially
verifiable. No scraped or unverified "hallucination lists" are shipped.
"""

# ---------------------------------------------------------------------------
# Popular packages, used ONLY for similarity ranking ("does this dependency
# look like a near-miss of something famous?"). All names below are extremely
# well-known, actively-maintained packages. The registry check decides whether
# a name actually exists; this list only powers suggestions.
# ---------------------------------------------------------------------------

POPULAR_PYTHON = frozenset({
    "numpy", "scipy", "pandas", "matplotlib", "seaborn", "requests",
    "urllib3", "flask", "django", "fastapi", "uvicorn", "gunicorn",
    "sqlalchemy", "alembic", "pytest", "black", "ruff", "mypy", "pylint",
    "torch", "torchvision", "torchaudio", "tensorflow", "keras",
    "transformers", "datasets", "accelerate", "peft", "trl",
    "scikit-learn", "xgboost", "lightgbm", "opencv-python", "pillow",
    "nltk", "spacy", "gensim", "boto3", "botocore", "openai", "anthropic",
    "langchain", "langgraph", "celery", "redis", "pymongo",
    "psycopg2-binary", "mysqlclient", "grpcio", "protobuf", "pydantic",
    "typer", "click", "rich", "tqdm", "loguru", "selenium", "playwright",
    "beautifulsoup4", "lxml", "scrapy", "httpx", "aiohttp", "paramiko",
    "cryptography", "pyjwt", "oauthlib", "pyyaml", "toml", "jsonschema",
    "virtualenv", "pip", "setuptools", "wheel", "poetry", "jupyter",
    "notebook", "ipykernel", "huggingface-hub", "safetensors", "tokenizers",
    "onnx", "onnxruntime", "faiss-cpu", "sentence-transformers",
})

POPULAR_NPM = frozenset({
    "react", "react-dom", "vue", "svelte", "@angular/core", "express",
    "next", "lodash", "axios", "chalk", "commander", "typescript", "eslint",
    "prettier", "jest", "vitest", "vite", "webpack", "rollup", "esbuild",
    "tailwindcss", "postcss", "socket.io", "mongoose", "prisma", "sequelize",
    "typeorm", "zod", "yup", "rxjs", "d3", "three", "gsap", "moment",
    "dayjs", "electron", "nodemon", "pm2", "dotenv", "jsonwebtoken",
    "bcrypt", "passport", "ws", "uuid", "nanoid", "cross-env", "rimraf",
    "glob", "execa", "ora", "inquirer", "prompts", "webpack-cli",
})

# ---------------------------------------------------------------------------
# Python import-name -> pip distribution name.
#
# A classic hallucination/slop pattern: the model writes `import cv2` and
# then tells you to `pip install cv2` (a name someone else may control).
# These mappings are standard, documented on each project's own install
# instructions (e.g. pillow, scikit-learn, pyyaml).
# ---------------------------------------------------------------------------

IMPORT_TO_DIST = {
    "cv2": "opencv-python",
    "pil": "pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "crypto": "pycryptodome",
    "openssl": "pyopenssl",
    "fitz": "pymupdf",
    "serial": "pyserial",
    "git": "gitpython",
    "github": "pygithub",
    "websocket": "websocket-client",
    "magic": "python-magic",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "cv": "opencv-python",
}

# Fallback minimal stdlib set for Python < 3.10 (where
# sys.stdlib_module_names is unavailable).
_FALLBACK_STDLIB = frozenset({
    "os", "sys", "json", "re", "math", "time", "datetime", "random",
    "logging", "collections", "itertools", "functools", "typing", "pathlib",
    "subprocess", "threading", "asyncio", "urllib", "socket", "hashlib",
    "base64", "uuid", "shutil", "tempfile", "unittest", "argparse", "enum",
    "abc", "io", "contextlib", "copy", "pickle", "sqlite3", "xml", "email",
    "http", "csv", "statistics", "string", "textwrap", "warnings", "heapq",
    "queue", "struct", "zlib", "gzip", "tarfile", "zipfile", "glob",
    "inspect", "importlib", "platform", "signal", "traceback", "types",
    "dataclasses", "secrets", "stat", "codecs", "locale", "zoneinfo",
})