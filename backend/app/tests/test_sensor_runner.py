import pytest
from pathlib import Path
from unittest.mock import MagicMock
from backend.app.pipeline.sensor_runner import run_sensor
from backend.app.sensors.registry import SensorDef

def test_run_sensor_docker_mounts(tmp_path):
    # Setup
    job_dir = tmp_path / "job-123"
    job_dir.mkdir()
    
    sensor_def = SensorDef(
        name="test_sensor",
        type="sensor",
        image="aipam/test-sensor:latest",
        enabled_by_default=True,
        mem_limit="512m",
        cpu_limit=0.5
    )
    
    mock_docker = MagicMock()
    # Mock images.get to avoid "Image not found" error
    mock_docker.images.get.return_value = MagicMock()
    
    # Mock container processes
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.return_value = b"test logs"
    mock_docker.containers.run.return_value = mock_container
    
    # Mock allowlist check
    with pytest.MonkeyPatch.context() as m:
        m.setattr("backend.app.pipeline.sensor_runner.validate_image_allowlist", lambda x: True)
        
        # Run
        result = run_sensor(
            sensor_def=sensor_def,
            job_dir=job_dir,
            job_id="job-123",
            execution_profile="standard",
            docker_client=mock_docker
        )
    
    # Verify result
    assert result.status == "completed"
    assert result.sensor == "test_sensor"
    
    # Verify docker call
    assert mock_docker.containers.run.called
    kwargs = mock_docker.containers.run.call_args.kwargs
    
    assert kwargs["image"] == "aipam/test-sensor:latest"
    assert kwargs["mem_limit"] == "512m"
    assert kwargs["cpu_quota"] == 50000  # 0.5 * 100,000
    
    # Verify volumes
    volumes = kwargs["volumes"]
    assert str(job_dir) in volumes
    assert volumes[str(job_dir)]["bind"] == "/input"
    assert volumes[str(job_dir)]["mode"] == "ro"
    
    output_dir = job_dir / "sensors" / "test_sensor"
    assert str(output_dir) in volumes
    assert volumes[str(output_dir)]["bind"] == "/output"
    assert volumes[str(output_dir)]["mode"] == "rw"
    
    # Verify environment
    env = kwargs["environment"]
    assert env["JOB_ID"] == "job-123"
    assert env["SENSOR_NAME"] == "test_sensor"
    assert env["EXECUTION_PROFILE"] == "standard"
    assert env["INPUT_DIR"] == "/input"
    assert env["OUTPUT_DIR"] == "/output"

def test_run_sensor_timeout(tmp_path):
    job_dir = tmp_path / "job-456"
    job_dir.mkdir()
    
    sensor_def = SensorDef(
        name="slow_sensor",
        type="sensor",
        image="aipam/slow:latest",
        timeout_seconds=1
    )
    
    mock_docker = MagicMock()
    mock_docker.images.get.return_value = MagicMock()
    
    mock_container = MagicMock()
    # Simulate timeout by raising exception in wait()
    mock_container.wait.side_effect = Exception("Read timeout")
    mock_docker.containers.run.return_value = mock_container
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("backend.app.pipeline.sensor_runner.validate_image_allowlist", lambda x: True)
        
        result = run_sensor(
            sensor_def=sensor_def,
            job_dir=job_dir,
            job_id="job-456",
            execution_profile="deep",
            docker_client=mock_docker
        )
    
    assert result.status == "timeout"
    assert "Timeout" in result.error
    assert mock_container.kill.called
