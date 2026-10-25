import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
MAIN=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/audit.py'))['main']

class DeadlineTests(unittest.TestCase):
    def test_past_deadline_completes_without_new_window(self):
        output=io.StringIO()
        with patch.object(sys,'argv',['audit','--deadline',str(time.time()-1)]),patch.dict(MAIN.__globals__,snapshot=lambda:{'reader_revision':2}),contextlib.redirect_stdout(output):
            self.assertEqual(MAIN(),0)
        rows=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(rows),2);self.assertTrue(rows[-1]['monitor_complete'])

    def test_refuse_incompatible_or_unbounded_windows(self):
        for args in (['--deadline','inf'],['--deadline','nan'],['--deadline',str(time.time()+200*3600)],['--deadline',str(time.time()+3600),'--monitor-hours','24']):
            with patch.object(sys,'argv',['audit']+args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                MAIN()

if __name__=='__main__':unittest.main()
