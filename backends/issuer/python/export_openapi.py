#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Provii

"""Export the OpenAPI specification from the FastAPI app to a JSON file.

Extracts the auto-generated OpenAPI schema from FastAPI, overrides metadata
fields for distribution, and writes the result to disk.

Usage: python export_openapi.py [output_path]
"""

import json
import sys
from pathlib import Path

from main import app


def export_openapi(output_path: str = "openapi.json") -> None:
    """Write the OpenAPI schema to a JSON file at the given path."""
    openapi_schema = app.openapi()

    openapi_schema["info"]["title"] = "Provii Issuer Backend API"
    openapi_schema["info"]["description"] = (
        "Third-party issuer backend API for requesting attestations from "
        "Provii's provii-issuer via HMAC-SHA256 authenticated requests. "
        "This is the API contract that issuers implement to integrate with Provii."
    )
    openapi_schema["servers"] = [
        {"url": "http://localhost:3000", "description": "Local development"},
        {
            "url": "https://your-issuer-backend.com",
            "description": "Production (replace with your URL)",
        },
    ]

    output = Path(output_path)
    output.write_text(json.dumps(openapi_schema, indent=2))
    print(f"OpenAPI spec exported to {output.absolute()}")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "openapi.json"
    export_openapi(output)
