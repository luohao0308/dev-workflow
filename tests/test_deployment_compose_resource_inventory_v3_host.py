"""Strict bounded API inventory projection; all data here is explicitly fixture data."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deployment_compose_resource_inventory_v3_host as inventory


class InventoryTests(unittest.TestCase):
    def values(self):
        return {inventory.CONTAINERS:[{'Id':'a'*64}],inventory.IMAGES:[{'Id':'sha256:'+'b'*64}],
            inventory.NETWORKS:[{'Id':'c'*64}],inventory.VOLUMES:{'Volumes':[{'Name':'v-one'}],'Warnings':None}}
    def test_fixed_endpoints_and_null_or_empty_warnings(self):
        values=self.values();paths=[]
        def get(path):paths.append(path);return values[path]
        result=inventory.inventory(get)
        self.assertEqual(paths,[inventory.CONTAINERS,inventory.IMAGES,inventory.NETWORKS,inventory.VOLUMES])
        self.assertEqual(result['volumes'],['v-one'])
        values[inventory.VOLUMES]['Warnings']=[]
        self.assertEqual(inventory.inventory(values.__getitem__),result)
    def test_duplicates_bad_types_partial_warnings_and_limits_reject(self):
        cases=[(inventory.CONTAINERS,None),(inventory.CONTAINERS,[{'Id':'a'*64}]*2),
            (inventory.IMAGES,[{'Id':'b'*64}]),(inventory.NETWORKS,[{'Id':'x'}]),
            (inventory.VOLUMES,{'Volumes':None,'Warnings':None}),
            (inventory.VOLUMES,{'Volumes':[],'Warnings':['partial']}),
            (inventory.VOLUMES,{'Volumes':[{'Name':'bad/name'}],'Warnings':None}),
            (inventory.CONTAINERS,[{'Id':'a'*64}]*513)]
        for path,bad in cases:
            with self.subTest(path=path,bad_type=type(bad)):
                values=self.values();values[path]=bad
                with self.assertRaises(ValueError):inventory.inventory(values.__getitem__)
    def test_order_is_canonical_and_unknown_rows_are_not_silently_dropped(self):
        values=self.values();values[inventory.CONTAINERS]=[{'Id':'b'*64},{'Id':'a'*64}]
        first=inventory.inventory(values.__getitem__)
        values[inventory.CONTAINERS].reverse()
        self.assertEqual(inventory.inventory(values.__getitem__),first)
        values[inventory.CONTAINERS].append({'Unknown':'hidden'})
        with self.assertRaises(ValueError):inventory.inventory(values.__getitem__)


if __name__=='__main__':unittest.main()
