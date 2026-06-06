# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""
Export the OpenAPI specification from the FastAPI app to a JSON file.

Usage: python export_openapi.py [output_path]

Defaults to writing openapi.json in the current directory.
"""

import json
import sys
from pathlib import Path

from main import app


def export_openapi(output_path: str = "openapi.json") -> None:
    """Extract the OpenAPI schema from the FastAPI app and write it to disk."""
    openapi_schema = app.openapi()

    openapi_schema["info"]["title"] = "Provii Verifier Backend API"
    openapi_schema["info"]["description"] = (
        "Third-party verifier backend API for age verification using Provii Wallet.\n\n"
        "This is the API contract that verifiers implement to integrate with Provii. "
        "The backend handles PKCE generation, HMAC authentication with provii-verifier, "
        "and secure code_verifier storage."
    )
    openapi_schema["servers"] = [
        {"url": "http://localhost:3001", "description": "Local development"},
        {
            "url": "https://your-verifier-backend.com",
            "description": "Production (replace with your URL)",
        },
    ]

    output = Path(output_path)
    output.write_text(json.dumps(openapi_schema, indent=2))
    print(f"OpenAPI spec exported to {output.absolute()}")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "openapi.json"
    export_openapi(output)
