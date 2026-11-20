from __future__ import annotations
import copy,json,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from release_qualification import build_qualification
from release_orchestrator import validate_controller_binding,validate_release_queue
from state_contracts import LEGACY_STATE_CONTRACT,ARCHIVE_STATE_CONTRACT


class ReleaseStateV2Tests(unittest.TestCase):
    def test_old_qualification_reconstruction_is_byte_identical_and_new_binds_actual_code(self):
        contract=json.loads((ROOT/'configuration/release-controller-credential-contract-v1.json').read_text())
        queue=json.loads((ROOT/'tests/fixtures/release-queue-v1.json').read_text())
        snapshot=json.loads((ROOT/'tests/fixtures/release-acceptance-snapshot-v1.json').read_text())
        args=dict(environment='production',publication_enabled='true',mode='publication',release_commit='a'*40,state_commit='b'*40)
        old=build_qualification(contract,queue,snapshot,**args)
        explicit=build_qualification(contract,queue,snapshot,state_contract_commit=LEGACY_STATE_CONTRACT,**args)
        self.assertEqual(old,explicit)
        new=build_qualification(contract,queue,snapshot,state_contract_commit=ARCHIVE_STATE_CONTRACT,**args)
        self.assertEqual(new,{**old,'state_contract_commit':ARCHIVE_STATE_CONTRACT})
        self.assertEqual(validate_controller_binding(new),new)
        with self.assertRaises(ValueError):build_qualification(contract,queue,snapshot,state_contract_commit='c'*40,**args)

    def test_historical_archive_tasks_are_not_ordinary_release_work(self):
        queue=json.loads((ROOT/'tests/fixtures/release-queue-v1.json').read_text())
        original=copy.deepcopy(queue)
        queue['tasks'][0]['fetch_method']='archive'
        with self.assertRaises(ValueError):validate_release_queue(queue)
        validate_release_queue(original)
