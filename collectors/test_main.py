import unittest
from unittest.mock import patch
from collectors.main import run_pipeline

class TestPipeline(unittest.TestCase):
    @patch("collectors.main.FEED_REGISTRY", [])
    def test_run_pipeline_invalid_name(self):
        run_pipeline("invalid_job")