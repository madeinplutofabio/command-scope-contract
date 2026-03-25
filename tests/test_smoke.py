def test_import():
    from importlib.metadata import version

    import csc_runner

    assert csc_runner.__version__ == version("csc-runner")
