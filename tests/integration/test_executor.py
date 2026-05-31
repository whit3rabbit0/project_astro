import pytest

from astro.core.executor import ToolExecutor


@pytest.fixture
def executor():
    return ToolExecutor()


class TestExecuteSuccess:
    async def test_echo_command(self, executor):
        result = await executor.execute(["echo", "hello"])
        assert result["success"] is True
        assert result["return_code"] == 0
        assert "hello" in result["stdout"]

    async def test_true_command(self, executor):
        result = await executor.execute(["true"])
        assert result["success"] is True
        assert result["return_code"] == 0


class TestExecuteFailure:
    async def test_nonexistent_command(self, executor):
        result = await executor.execute(["nonexistent_command_xyz"])
        assert result["success"] is False
        assert result["return_code"] == -1

    async def test_false_command(self, executor):
        result = await executor.execute(["false"])
        assert result["success"] is False
        assert result["return_code"] == 1


class TestExecuteTimeout:
    async def test_timeout_handling(self, executor):
        result = await executor.execute(["sleep", "10"], timeout=1)
        assert result["success"] is False
        assert "timed out" in result["stderr"].lower()
        assert result["return_code"] == -1


class TestExecuteOutput:
    async def test_captures_stdout(self, executor):
        result = await executor.execute(["echo", "test output"])
        assert result["stdout"].strip() == "test output"

    async def test_captures_stderr(self, executor):
        result = await executor.execute(["ls", "/nonexistent_path_xyz"])
        assert result["stderr"] != ""
        assert result["success"] is False

    async def test_result_keys(self, executor):
        result = await executor.execute(["echo", "hi"])
        assert "stdout" in result
        assert "stderr" in result
        assert "return_code" in result
        assert "success" in result
