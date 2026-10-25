import concurrent.futures
from pathlib import Path
import runpy
import unittest

STATE=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/firewall_state.py'))

class PortConcurrency(unittest.TestCase):
    def test_four_and_eight_threads(self):
        cases=[('http,https','tcp',[(80,80),(443,443)]),
               ('ssh,http,https','tcp',[(22,22),(80,80),(443,443)]),
               ('domain','udp',[(53,53)]),('80:443','tcp',[(80,443)])]
        def probe(i):
            value,protocol,wanted=cases[i%len(cases)]
            return STATE['ranges'](value,protocol)==wanted
        for workers in (4,8):
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                self.assertTrue(all(pool.map(probe,range(20000))),workers)

    def test_invalid(self):
        for value in ('443:80','65536','80:90:100','-1','80:',':443'):
            with self.assertRaises((ValueError,OSError)):STATE['ranges'](value)
        with self.assertRaises(OSError):STATE['ranges']('amsfb-service-does-not-exist')
        with self.assertRaises(ValueError):STATE['ranges']('80','sctp')
        self.assertEqual(STATE['ranges']('http-alt'),[(8080,8080)])

if __name__=='__main__':unittest.main()
