"""Manual pipeline smoke-test script.

This is intentionally **not** a pytest test; it's a helper you can run
manually against a running backend. It is excluded from pytest collection
by design so that the unit test suite does not require the `requests`
package or a live HTTP server.

Usage (from backend/):

    python test_pipeline_manual.py

You can then uncomment the `requests` calls below and install
`requests` in your own environment if you want an end-to-end HTTP test.
"""

if __name__ == "__main__":
    print("Manual pipeline test helper; see docstring for usage.")
